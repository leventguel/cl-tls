(defpackage :tls-utils
  (:use :cl)
  (:export
   :print-hex :wrap-in-tls-record :read-cert-from-file
   :write-hex-lines :dump-record :generate-random-data :generate-verify-data
   :extract-random-from-hello :derive-key-block :xor-bytes :split-into-blocks
   :build-handshake-transcript))

(in-package :tls-utils)

(defun print-hex (buf)
  (loop for byte across buf do
    (format t "0x~2,'0X " byte))
  (terpri))

(defun words-to-bytes (words)
  (let ((bytes (make-array (* 4 (length words)) :element-type '(unsigned-byte 8))))
    (loop for i from 0 below (length words)
          for word = (aref words i)
          for base = (* i 4)
          do (setf (aref bytes base)     (ldb (byte 8 24) word)
                   (aref bytes (+ base 1)) (ldb (byte 8 16) word)
                   (aref bytes (+ base 2)) (ldb (byte 8 8) word)
                   (aref bytes (+ base 3)) (ldb (byte 8 0) word)))
    bytes))

(defun hmac (key message hash-fn block-size output-size)
  (let* ((key (if (> (length key) block-size)
                  (funcall hash-fn key)
                  key))
         (key (concatenate '(vector (unsigned-byte 8))
                           key
                           (make-array (- block-size (length key))
                                       :element-type '(unsigned-byte 8)
                                       :initial-element 0)))
         (ipad (make-array block-size :element-type '(unsigned-byte 8)
                                      :initial-element #x36))
         (opad (make-array block-size :element-type '(unsigned-byte 8)
                                      :initial-element #x5c)))
    ;; XOR key with ipad and opad
    (loop for i from 0 below block-size do
      (setf (aref ipad i) (logxor (aref ipad i) (aref key i))
            (aref opad i) (logxor (aref opad i) (aref key i))))
    ;; Compute HMAC
    (words-to-bytes (funcall hash-fn
                             (concatenate '(vector (unsigned-byte 8))
                                          opad
                                          (words-to-bytes (funcall hash-fn
                                                                   (concatenate '(vector (unsigned-byte 8))
                                                                                ipad
                                                                                message))))))))

(defun wrap-in-tls-record (handshake-message)
  "Wraps a TLS handshake message in a TLS record header."
  (let* ((content-type  #x16)  ; Handshake
         (version-major #x03)
         (version-minor #x03)
         (length (length handshake-message)))
    (concatenate '(vector (unsigned-byte 8))
                 (vector content-type version-major version-minor
                         (ldb (byte 8 8) length)
                         (ldb (byte 8 0) length))
                 handshake-message)))

(defun read-cert-from-file (path)
  "Reads a DER-encoded certificate from a file into a byte vector."
  (with-open-file (stream path :element-type '(unsigned-byte 8))
    (let ((data (make-array (file-length stream)
                            :element-type '(unsigned-byte 8))))
      (read-sequence data stream)
      data)))

;; Use it like (build-handshake-transcript hello cert done) for off the flow testing/constructing message sequences
;; i.e. outside full protocol orchestration
;; (build-handshake-transcript (build-client-hello-record) (build-server-hello-record) (build-server-cert-record)
;; (build-server-hello-done-record) (build-client-key-exchange-record) (build-change-cipher-spec-record)
;; (build-server-finished-record))
;; which is just the logical flow without the verification part
(defun build-handshake-transcript (&rest records)
  (apply #'concatenate '(vector (unsigned-byte 8)) (copy-seq records)))

;; binary
(defun dump-record (bytes &optional (path "~/clocc/src/ssl/server-handshake.bin"))
  (with-open-file (stream path
                          :direction :output
                          :element-type '(unsigned-byte 8)
                          :if-exists :supersede
                          :if-does-not-exist :create)
    (write-sequence bytes stream)))

;; hex text
(defun write-hex-lines (bytes filename)
  (with-open-file (out filename :direction :output :if-exists :supersede)
    (loop for i from 0 below (length bytes) by 16
          for chunk = (subseq bytes i (min (+ i 16) (length bytes)))
          do (format out "~4,'0X  " i)
             (loop for b across chunk do (format out "~2,'0X " b))
             (terpri out))))

(defun generate-random-data (length)
  (let ((random-bytes (make-array length :element-type '(unsigned-byte 8))))
    (dotimes (i length)
      (setf (aref random-bytes i) (random 256)))
    random-bytes))

(defun generate-verify-data (handshake-transcript
                             master-secret
                             &key (digest 'sha256) (mac-size 12))
  "Computes TLS Finished message verify_data from transcript and master secret."
  (let ((transcript-hash (words-to-bytes (funcall digest handshake-transcript))))
    (subseq
     (hmac master-secret transcript-hash digest
           ;; Block size: 64 for SHA-256/224/1, 128 for SHA-384/512
           (case digest
             ((sha384 sha512) 128)
             (t 64))
           mac-size)
     0 mac-size)))

(defun extract-random-from-hello (hello-record)
  "Extracts 32-byte random from TLS Hello message.
Assumes TLS record header is 5 bytes and handshake header is 4 bytes.
Random begins at byte offset 10."
  ;; Assuming TLS record header is 5bytes
  ;; Handshake header is 4bytes
  ;; Random starts at byte 6 + 4 = offset 10
  (subseq hello-record 10 42))

(defun derive-key-block (master-secret
                         server-random client-random
                         total-length
                         &key (digest 'sha256))
  "Derives key block from TLS master secret using PRF expansion."
  (let* ((label (map 'vector #'char-code "key expansion"))
         (seed (concatenate '(vector (unsigned-byte 8)) label server-random client-random)))
    (subseq
     (hmac master-secret seed digest
           (case digest ((sha384 sha512) 128) (t 64))
           total-length)
     0 total-length)))


;; aes stuff
(defun xor-bytes (a b)
  "XORs two byte vectors of equal length."
  (let ((len (length a)))
    (coerce (loop for i from 0 below len
                  collect (logxor (aref a i) (aref b i)))
            '(vector (unsigned-byte 8)))))

(defun split-into-blocks (data &optional (block-size 16))
  "Splits byte vector into list of block-sized vectors."
  (loop for i from 0 below (length data) by block-size
        collect (subseq data i (min (+ i block-size) (length data)))))

#|
(defun aes-cbc-encrypt-ironclad (plaintext key iv)
"Encrypts plaintext using AES-128-CBC. Requires Ironclad."
(let ((ctx (ironclad:make-cipher :aes :mode :cbc :key key :iv iv)))
(ironclad:encrypt-sequence ctx plaintext)))
|#
