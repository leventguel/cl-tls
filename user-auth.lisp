(defpackage :tls-user-auth
  (:use :cl :des-utils :sha256 :hmac-sha256 :tls-pkbdf2 :tls-aes256)
  (:export :*user-db* :split-lines :read-auth-record :serialize-auth-record :deserialize-auth-record
	   :register-user :authenticate-user))

(in-package :tls-user-auth)

(defparameter *user-db* (make-hash-table :test 'equal))
(defparameter *master-key* #(1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16)) ; 128-bit AES key
(defparameter *mac-key* #(16 15 14 13 12 11 10 9 8 7 6 5 4 3 2 1))   ; HMAC key

(defun load-user-records (directory)
  "Load all .auth files from DIRECTORY into *user-db*."
  (ensure-directories-exist directory)
  (dolist (file (directory (merge-pathnames "*.auth" directory)))
    (let* ((record (read-auth-record file))
           (data (deserialize-auth-record record)))
      (setf (gethash (pathname-name file) *user-db*) data))))

(defun generate-iv ()
  "Generate a 16-byte initialization vector for AES."
  (generate-salt 16))

(defun encrypt-record (plaintext master-key)
  "Encrypts PLAINTEXT using MASTER-KEY (a byte vector)."
  (aes:encrypt-cbc plaintext master-key (generate-iv)))

(defun add-mac (plaintext mac-key)
  "Appends HMAC-SHA256 to PLAINTEXT using MAC-KEY."
  (let ((mac (hmac-sha256 mac-key plaintext)))
    (concatenate 'vector plaintext mac)))

(defun secure-save-auth-record-manual (filename salt key iterations length master-key mac-key)
  (let* ((plaintext (serialize-auth-record salt key iterations length))
         (mac-appended (add-mac (map 'vector #'char-code plaintext) mac-key))
         (ciphertext (encrypt-record mac-appended master-key)))
    (with-open-file (out filename :direction :output :if-exists :supersede :element-type '(unsigned-byte 8))
      (write-sequence ciphertext out))))

(defun secure-save-auth-record (filename salt key iterations length)
  "Encrypt and save the auth record with integrity protection."
  (let* ((plaintext (serialize-auth-record salt key iterations length))
         (plaintext-bytes (map 'vector #'char-code plaintext))
         (mac (hmac-sha256:hmac-sha256 *mac-key* plaintext-bytes))
         (mac-appended (concatenate 'vector plaintext-bytes mac))
         (iv (generate-salt 16)) ; reuse your salt generator for IV
         (ciphertext (aes:encrypt-cbc mac-appended *master-key* iv))
         (final (concatenate 'vector iv ciphertext)))
    (with-open-file (out filename :direction :output :if-exists :supersede :element-type '(unsigned-byte 8))
      (write-sequence final out))))

(defun secure-load-auth-record-manual (filename master-key mac-key)
  (with-open-file (in filename :direction :input :element-type '(unsigned-byte 8))
    (let* ((ciphertext (read-sequence in (make-array (file-length in) :element-type '(unsigned-byte 8))))
           (mac-appended (aes:decrypt-cbc ciphertext master-key))
           (plaintext (subseq mac-appended 0 (- (length mac-appended) 32)))
           (mac (subseq mac-appended (- (length mac-appended) 32))))
      (when (equal mac (hmac-sha256 mac-key plaintext))
        (deserialize-auth-record (coerce plaintext 'string))))))

(defun rotate-master-key (filename old-key new-key mac-key)
  (let ((data (secure-load-auth-record-manual filename old-key mac-key)))
    (secure-save-auth-record-manual filename
                                     (getf data :salt)
                                     (hex-string-to-byte-vector (getf data :key))
                                     (getf data :iterations)
                                     (getf data :length)
                                     new-key
                                     mac-key)))

(defun secure-load-auth-record (filename)
  "Load and decrypt the auth record, verifying integrity."
  (with-open-file (in filename :direction :input :element-type '(unsigned-byte 8))
    (let* ((file-size (file-length in))
           (data (make-array file-size :element-type '(unsigned-byte 8)))
           (_ (read-sequence data in))
           (iv (subseq data 0 16))
           (ciphertext (subseq data 16))
           (mac-appended (aes:decrypt-cbc ciphertext *master-key* iv))
           (plaintext (subseq mac-appended 0 (- (length mac-appended) 32)))
           (mac (subseq mac-appended (- (length mac-appended) 32))))
      (if (equal mac (hmac-sha256:hmac-sha256 *mac-key* plaintext))
          (deserialize-auth-record (coerce plaintext 'string))
          (error "MAC verification failed — record may be tampered.")))))

(defun split-lines (str)
  "Split STR into lines using built-in Common Lisp."
  (let ((start 0)
        lines)
    (loop for i from 0 below (length str)
          when (char= (char str i) #\Newline)
            do (push (subseq str start i) lines)
               (setf start (1+ i)))
    (when (< start (length str))
      (push (subseq str start) lines))
    (nreverse lines)))

(defun read-auth-record (filename)
  "Reads the entire contents of the file as a single string."
  (with-open-file (in filename :direction :input)
    (let ((lines))
      (loop for line = (read-line in nil nil)
            while line
            do (push line lines))
      (format nil "~{~A~%~}" (nreverse lines)))))

(defun serialize-auth-record (salt key &optional (iterations 100000) (length 32))
  "Serialize salt and derived key into a string."
  (format nil "~{~2,'0X~}~%~A~%~D~%~D"
          (coerce salt 'list)
          (hmac-sha256:bytes-to-hex key)
          iterations
          length))

(defun deserialize-auth-record (record)
  "Deserialize a string into salt, key, iterations, and length."
  (let ((lines (split-lines record)))
    (list :salt (first lines)
          :key (second lines)
          :iterations (parse-integer (third lines))
          :length (parse-integer (fourth lines)))))

(defun register-user (username password &optional (iterations 100000) (length 32))
  "Registers a user by storing salt and derived key."
  (let* ((salt (generate-salt))
         (password-bytes (map 'vector #'char-code password))
         (key (derive-key password-bytes salt :iterations iterations :length length)))
    (setf (gethash username *user-db*)
          (list :salt salt
                :key (hmac-sha256:bytes-to-hex key)
                :iterations iterations
                :length length))
    (format t "User ~A registered.~%" username)))

(defun authenticate-user (username password)
  "Verifies password for a given user."
  (let ((user-data (gethash username *user-db*)))
    (if user-data
        (destructuring-bind (&key salt key iterations length) user-data
          (let* ((password-bytes (map 'vector #'char-code password))
                 (derived-key (derive-key password-bytes salt :iterations iterations :length length))
                 (derived-hex (hmac-sha256:bytes-to-hex derived-key)))
            (string= derived-hex key)))
        (progn
          (format t "User ~A not found.~%" username)
          nil))))

(defun example-flow1 ()
  ;; without secure versions
  ;; Save to file
  (with-open-file (out "user-auth.auth" :direction :output :if-exists :supersede)
    (let* ((salt (generate-salt))
          (key (derive-key (map 'vector #'char-code "hunter3") salt)))
      (write-line (serialize-auth-record salt key) out)))
  
  ;; Load and verify
  (with-open-file (in "user-auth.auth" :direction :input)
    (let ((record (read-auth-record in)))
      (let ((data (deserialize-auth-record record)))
	(pw-verify "hunter3"
                   (getf data :salt)
                   (getf data :key)
                   (getf data :iterations)
                   (getf data :length))))))

(example-flow)

(defun example-flow2 ()
  ;; with secure versions
  ;; Save to file
  (with-open-file (out "user-auth.auth" :direction :output :if-exists :supersede)
    (let* ((salt (generate-salt))
          (key (derive-key (map 'vector #'char-code "hunter3") salt)))
      (write-line (serialize-auth-record salt key) out)))
  
  ;; Load and verify
  (with-open-file (in "user-auth.auth" :direction :input)
    (let ((record (secure-load-auth-record in)))
      (let ((data (deserialize-auth-record record)))
	(pw-verify "hunter3"
                   (getf data :salt)
                   (getf data :key)
                   (getf data :iterations)
                   (getf data :length))))))
