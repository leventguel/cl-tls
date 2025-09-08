(defpackage :x509-system
  (:use :cl)
  (:export :load-x509))

(in-package :x509-system)

(defun load-x509 ()
  (load "x509-parser/x509/x509-fields.lisp")
  (load "x509-parser/x509/x509-parser.lisp")
  (load "x509-parser/x509/x509-verify.lisp")
  (load "x509-parser/x509/test-x509.lisp"))
