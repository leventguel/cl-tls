(defpackage :tls-aes-ghash
  (:use :cl)
  (:export :int->block-64be :ghash))

(in-package :tls-aes-ghash)

;; GHASH finite field polynomial for GF(2^128)
(defparameter *ghash-polynomial*
  #xE1000000000000000000000000000000)

;; Convert 16-byte vector to bignum
(defun block->int (block)
  "Converts 128-bit block to bignum."
  (reduce (lambda (acc byte)
            (logior (ash acc 8) byte))
          block
          :initial-value 0))

;; Convert bignum to 16-byte vector
(defun int->block (n)
  "Converts bignum to 128-bit block (vector of bytes)."
  (let ((vec (make-array 16 :element-type '(unsigned-byte 8))))
    (dotimes (i 16)
      (setf (aref vec (- 15 i)) (ldb (byte 8 (* i 8)) n)))
    vec))

(defun int->block-64be (n)
  "Converts integer to 8-byte big-endian block."
  (let ((bytes (make-array 8 :element-type '(unsigned-byte 8))))
    (dotimes (i 8)
      (setf (aref bytes (- 7 i)) (ldb (byte 8 (* i 8)) n)))
    bytes))

(defun gf128-mul (x y)
  (let ((res 0)
        (R #xE1000000000000000000000000000000)
        (mask #xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF))
    (dotimes (i 128)
      (when (logbitp (- 127 i) y)
        (setf res (logxor (logand res mask) x)))
      (setf res (logand res mask)) ;; ✨ constrain res to 128 bits
      (setf x (if (logbitp 0 x)
                  (logand (logxor (ash x -1) R) mask)
                  (logand (ash x -1) mask)))
      (setf x (logand x mask)))
    res))

;; GHASH: authenticated hash of input blocks
(defun ghash (h blocks)
  (let ((h-int (block->int h))
        (y 0))
    (dolist (block blocks)
      (setf y (gf128-mul h-int (logxor y (block->int block)))))
    (int->block y)))
