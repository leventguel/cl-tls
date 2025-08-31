(defpackage :tls-aes-ghash
  (:use :cl :shared-utils :tls-aes-utils :gf128-mul)
  (:export :ghash))

(in-package :tls-aes-ghash)

;; GHASH: authenticated hash of input blocks
(defun ghash (h blocks)
  (let ((h-int (block->int h))
        (y 0))
    (dolist (block blocks)
      (setf y (gf128-mul h-int (logxor y (block->int block)))))
    (int->block y)))
