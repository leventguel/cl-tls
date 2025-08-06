(defpackage :hmac-sha384
  (:use :cl :tls-utils :sha384)
  (:export :hmac-sha384 :hmac-sha384-hex))

(in-package :hmac-sha384)

(defun words64-to-bytes (words)
  (let ((bytes (make-array (* 8 (length words)) :element-type '(unsigned-byte 8))))
    (loop for i from 0 below (length words)
          for word = (aref words i)
          for base = (* i 8)
          do (loop for j from 0 below 8
                   for shift = (* 8 (- 7 j))
                   do (setf (aref bytes (+ base j))
                            (ldb (byte 8 shift) word))))
    bytes))

(defun bytes-to-hex (digest)
  (string-downcase
   (with-output-to-string (s)
     (loop for word across digest
           do (loop for shift from 56 downto 0 by 8
                    do (format s "~2,'0X" (ldb (byte 8 shift) word)))))))

(defun hmac-sha384 (key message)
  (let* ((block-size 128)
         (key (if (> (length key) block-size)
                  (sha384 (coerce key '(vector (unsigned-byte 8))))
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
    ;; Inner and outer hashes
    (sha384
     (concatenate '(vector (unsigned-byte 8))
                  opad
                  (words64-to-bytes (sha384
                                     (concatenate '(vector (unsigned-byte 8)) ipad message)))))))

(defun hmac-sha384-hex (key message)
  (bytes-to-hex (hmac-sha384 key message)))

(let ((key (make-array 48 :element-type '(unsigned-byte 8) :initial-element #x0b))
      (msg (map 'vector #'char-code "Hi There")))
  (let ((raw-digest (hmac-sha384 key msg))
        (hex-digest
          (bytes-to-hex (hmac-sha384 key msg))))
    (format t "HMAC-SHA384: ~A~%" (string-downcase hex-digest))))
