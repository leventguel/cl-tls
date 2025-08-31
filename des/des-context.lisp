(defpackage :des-context
  (:use :cl :des-core)
  (:export :make-des-context-from-key :des-context-encrypt-block :des-context-decrypt-block))

(in-package :des-context)

(defstruct des-context
  key
  round-keys)

(defun make-des-context-from-key (key)
  (make-des-context key (generate-round-keys key)))

(defun des-context-encrypt-block (ctx block)
  (des-ecb-encrypt-block block (des-context-round-keys ctx)))

(defun des-context-decrypt-block (ctx block)
  (des-ecb-decrypt-block block (des-context-round-keys ctx)))
