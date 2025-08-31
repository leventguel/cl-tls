(defpackage :tls-pkbdf2
  (:use :cl :des-utils :sha256 :hmac-sha256)
  (:export :encode-block-index :seed-random :generate-salt :pkbdf2 :derive-key :pkbdf2-encode :pw-encode-test :pw-encode :pw-verify))

(in-package :tls-pkbdf2)

(defun encode-block-index (index)
  "Encode a 32-bit integer INDEX into a 4-byte big-endian vector."
  (let ((bytes (make-array 4 :element-type '(unsigned-byte 8))))
    (setf (aref bytes 0) (ldb (byte 8 24) index)
          (aref bytes 1) (ldb (byte 8 16) index)
          (aref bytes 2) (ldb (byte 8 8) index)
          (aref bytes 3) (ldb (byte 8 0) index))
    bytes))

(defun seed-random ()
  "Seeds the random number generator using current time."
  (let ((seed (get-universal-time)))
    (setf *random-state* (make-random-state t))
    (random seed)))

(defun generate-salt (&optional (length 16))
  "Generates a random salt vector of LENGTH bytes using built-in random."
  (let ((salt (make-array length :element-type '(unsigned-byte 8))))
    (dotimes (i length)
      (setf (aref salt i) (random 256)))
    salt))

(defun pbkdf2 (password salt iterations dklen)
  (let* ((block-size 32)
         (num-blocks (ceiling dklen block-size))
         (derived-key (make-array dklen :element-type '(unsigned-byte 8))))
    (loop for block-index from 1 to num-blocks
          for block-index-bytes = (encode-block-index block-index)
          for hmac-result = (hmac-sha256:hmac-sha256 password (concatenate 'vector salt block-index-bytes))
          for xor-accumulator = (copy-seq hmac-result)
          for key-offset = (* (1- block-index) block-size)
          do (loop repeat (1- iterations)
                   do (setf hmac-result (hmac-sha256:hmac-sha256 password hmac-result))
                   (loop for j from 0 below block-size
                         do (setf (aref xor-accumulator j)
                                  (logxor (aref xor-accumulator j) (aref hmac-result j))))
             (loop for j from 0 below (min block-size (- dklen key-offset))
                   do (setf (aref derived-key (+ key-offset j)) (aref xor-accumulator j)))))
	  derived-key))

(defun derive-key (password salt &key (iterations 100000) (length 32))
  (pbkdf2 password salt iterations length))

;; example usage
(defun pkbdf2-encode (password)
  (let ((password (map 'vector #'char-code password))
	(salt #(#xDE #xAD #xBE #xEF))
	(iterations 100000)
	(dklen 32))
    (format t "Derived key: ~A~%"
            (hmac-sha256:bytes-to-hex (pbkdf2 password salt iterations dklen)))))

(pkbdf2-encode "hunter")

;; example usage
(defun pw-encode-test (pw &optional (salt #(#xDE #xAD #xBE #xEF)) (iterations 100000) (length 32))
  "Encodes pw with pkbdf2"
  (let* ((password (map 'vector #'char-code pw))
	 (key (derive-key password salt :iterations iterations :length length)))
    (format t "Derived key: ~A~%"
            (hmac-sha256:bytes-to-hex key))))

(pw-encode-test "hunter2")

(defun pw-encode (pw &optional (salt (generate-salt)) (iterations 100000) (length 32))
  "Encodes pw with PBKDF2 using internally generated salt."
  (let* ((password (map 'vector #'char-code pw))
         (key (derive-key password salt :iterations iterations :length length)))
    ;;(format t "Salt: ~{~2,'0X~}~%" (coerce salt 'list))
    (format t "Salt+Key: ~{~2,'0X~}~A~%" (coerce salt 'list) (hmac-sha256:bytes-to-hex key))
    (format t "Derived key: ~A~%" (hmac-sha256:bytes-to-hex key))))

(pw-encode "hunter3")

(defun pw-verify (pw stored-salt stored-key &optional (iterations 100000) (length 32))
  "Verifies if PW matches the stored derived key using the stored salt."
  (let* ((password (map 'vector #'char-code pw))
         (salt (hex-string-to-byte-vector stored-salt))
         (derived-key (derive-key password salt :iterations iterations :length length))
         (derived-hex (hmac-sha256:bytes-to-hex derived-key)))
    (string= derived-hex stored-key)))
