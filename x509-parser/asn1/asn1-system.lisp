(defpackage :asn1-system
  (:use :cl)
  (:export :load-asn1))

(in-package :asn1-system)

(defun load-asn1 ()
  (load "x509-parser/asn1/asn1-types.lisp")
  (load "x509-parser/asn1/asn1-schema.lisp")
  (load "x509-parser/asn1/asn1-utils.lisp")
  (load "x509-parser/asn1/asn1-parser.lisp")
  (load "x509-parser/asn1/asn1-encoders.lisp")
  (load "x509-parser/asn1/asn1-extractors.lisp"))
