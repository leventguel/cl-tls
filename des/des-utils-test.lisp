(defpackage :des-utils-test
  (:use :cl :des-utils))

(in-package :des-utils-test)

(defmacro test (form)
  `(if ,form
       (progn (format t "PASS: ~A~%" ',form) t)
       (progn (format t "FAIL: ~A~%" ',form) nil)))


(test (equalp (bit-vector-to-byte-vector (byte-vector-to-bit-vector #(255))) #(255)))
(test (des-block-p (make-array 64 :element-type '(unsigned-byte 1))))

(print (assert (equalp (bit-vector-to-byte-vector (byte-vector-to-bit-vector #(255))) #(255))))
(print (assert (des-block-p (make-array 64 :element-type '(unsigned-byte 1)))))
