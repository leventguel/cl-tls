(defpackage :hmac
  (:use :cl :shared-utils :sha-utils :hmac-sha256)
  (:export :hmac :hmac-hex))

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

(defun hmac-hex (bytes)
  (with-output-to-string (s)
    (loop for b across bytes
          do (format s "~2,'0X" b))))

;; Key: 20 bytes of 0x0b
;; Message: "Hi There"
;; Expected HMAC-SHA256:
;; b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7

(load "~/clocc/src/ssl/sha256.lisp")
(load "~/clocc/src/ssl/sha224.lisp")

(let ((key (make-array 20 :element-type '(unsigned-byte 8) :initial-element #x0b))
      (msg (map 'vector #'char-code "Hi There")))
  (format t "HMAC-SHA256: ~A~%" (string-downcase (hmac-hex (hmac-sha256 key msg)))))

