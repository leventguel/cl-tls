(defpackage :rsa-core
  (:use :cl :rsa-utils)
  (:export :rsa-verify))

(in-package :rsa-core)

(defun rsa-verify (signature e n)
  (mod-exp signature e n)) ;; returns decrypted DigestInfo
