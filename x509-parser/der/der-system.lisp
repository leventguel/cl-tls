(defpackage :der-system
  (:use :cl)
  (:export :load-der))

(in-package :der-system)

(defun load-der ()
  (load "x509-parser/der/der-utils.lisp")
  (load "x509-parser/der/der-parser.lisp"))
