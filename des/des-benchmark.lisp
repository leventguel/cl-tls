(defpackage :des-benchmark
  (:use :cl :des-core :des-context)
  (:export :benchmark-des))

(defun benchmark-des (n)
  (let ((key (hex-string-to-byte-vector "133457799BBCDFF1"))
        (block (hex-string-to-byte-vector "0123456789ABCDEF"))
        (ctx (make-des-context key)))
    (time (dotimes (i n)
            (des-context-encrypt-block ctx block)))))
