(defpackage :rsa-system
  (:use :cl)
  (:export :load-rsa))

(in-package :rsa-system)

(defun load-rsa ()
  (load "x509-parser/crypto/rsa-utils.lisp")
  (load "x509-parser/crypto/rsa-pkcs1.lisp")
  (load "x509-parser/crypto/rsa-core.lisp")
  (load "x509-parser/crypto/rsa-key.lisp"))
