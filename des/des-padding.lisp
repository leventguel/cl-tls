(defpackage :des-padding
  (:use :cl :shared-utils :des-utils)
  (:export :pad-blocks :unpad-blocks :pad-byte-vector :unpad-byte-vector))

(in-package :des-padding)

;; PKCS#7 padding and unpadding
(defun pad-blocks (bytes block-size)
  "Add PKCS#7 padding to byte vector"
  (unless (plusp block-size)
    (error "Block size must be positive"))
  (when (> block-size 255)
  (error "Block size too large for PKCS#7"))
  (let* ((pad-len (- block-size (mod (length bytes) block-size)))
         (padding (make-array pad-len :element-type '(unsigned-byte 8)
                              :initial-element pad-len)))
    (concatenate 'vector bytes padding)))

(defun unpad-blocks (bytes)
  "Remove PKCS#7 padding from byte vector."
  (let* ((len (length bytes))
         (pad-len (aref bytes (1- len))))
    (if (and (> pad-len 0) (<= pad-len 8)
             (every (lambda (b) (= b pad-len))
                    (subseq bytes (- len pad-len) len)))
        (subseq bytes 0 (- len pad-len))
        (error "Invalid padding detected"))))

(defun pad-byte-vector (bytes block-size)
  (pad-blocks bytes block-size))

(defun unpad-byte-vector (bytes)
  (unpad-blocks bytes))
