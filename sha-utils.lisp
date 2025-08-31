(defpackage :sha-utils
  (:use :cl)
  (:export :rotl32 :rotr32 :rotr64 :shr32 :shr64 :ch :maj :bytes-to-hex))

(in-package :sha-utils)

(defun rotl32 (x n)
  (mod (logior (ash x n)
               (ash x (- n 32)))
       #x100000000))

(defun rotr32 (x n)
  (mod (logior (ash x (- n))
               (ash x (- 32 n)))
       #x100000000))

;; SHA-384 Initial Hash Values (from FIPS 180-4)
(defun rotr64 (x n)
  (mod (logior (ash x (- n))
               (ash x (- 64 n)))
       #x10000000000000000))

(defun shr32 (x n) (mod (ash x (- n)) #x100000000))
(defun shr64 (x n) (mod (ash x (- n)) #x10000000000000000))

(defun ch (x y z) (logxor (logand x y) (logand (lognot x) z)))
(defun maj (x y z) (logxor (logand x y) (logand x z) (logand y z)))

(defun bytes-to-hex (bytes)
  (with-output-to-string (s)
    (loop for b across bytes
          do (format s "~2,'0X" b))))
