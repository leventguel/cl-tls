;; test-hmac-sha384-random.lisp

(load "~/clocc/src/ssl/sha384.lisp")
(load "~/clocc/src/ssl/hmac-sha384.lisp")
(load "~/clocc/src/ssl/generate-random-key.lisp")

(defun word64-vector-to-byte-array (v)
  "Convert a vector of 64-bit unsigned integers into a byte array."
  (let ((out (make-array (* (length v) 8) :element-type '(unsigned-byte 8))))
    (loop for i from 0 below (length v)
          for word = (aref v i)
          do (loop for shift from 56 downto 0 by 8
                   for j from 0
                   for byte = (ldb (byte 8 shift) (coerce word 'integer)) ; Force conversion
                   do (setf (aref out (+ (* i 8) j)) byte)))
    out))

(defun bytes-to-hex (byte-array)
  "Convert vector of (unsigned-byte 8) to lowercase hexadecimal string."
  (string-downcase
   (with-output-to-string (s)
     (loop for b across byte-array
           do (format s "~2,'0X" b)))))

(defun hmac-sha384-hex-fixed (key message)
  "Run HMAC-SHA384 and get hex output by expanding digest properly."
  (bytes-to-hex (word64-vector-to-byte-array
                 (hmac-sha384 key message))))

;; Generate secure random key and message
(defparameter *key* (os-random-bytes 48)) ; 48 bytes for SHA-384
(defparameter *message* (map 'vector #'char-code "TLS test message"))

(format t "~%✅ HMAC-SHA384 Digest: ~A~%" (hmac-sha384-hex-fixed *key* *message*))
