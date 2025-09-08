(defpackage :rsa-utils
  (:use :cl :shared-utils)
  (:export :mod-exp :mod-inverse :extended-gcd
	   :random-bignum :random-odd-bignum :generate-prime
	   :probably-prime-p))

(in-package :rsa-utils)

(defun mod-exp (base exp modulus)
  ;; Fast modular exponentiation (square-and-multiply)
  (loop with result = 1
        while (> exp 0)
        do (when (oddp exp)
             (setf result (mod (* result base) modulus)))
           (setf base (mod (* base base) modulus))
           (setf exp (floor exp 2))
        finally (return result)))

(defun mod-inverse (a m)
  (multiple-value-bind (g x y) (extended-gcd a m)
    (if (= g 1)
        (mod x m)
        nil))) ;; no inverse if gcd ≠ 1

(defun extended-gcd (a b)
  (if (= b 0)
      (values a 1 0)
      (multiple-value-bind (g x1 y1) (extended-gcd b (mod a b))
        (values g y1 (- x1 (* (floor a b) y1))))))

(defun random-bignum (bits)
  (let ((bytes (make-array (ceiling bits 8) :element-type '(unsigned-byte 8)
                           :initial-element 0)))
    (loop for i below (length bytes)
          do (setf (aref bytes i) (random 256)))
    (setf (aref bytes 0) (logior (aref bytes 0) 128)) ;; ensure high bit set
    (byte-vector-to-integer bytes)))

(defun random-odd-bignum (bits)
  (let ((n (random-bignum bits)))
    (logior n 1))) ;; ensure odd

;; Miller-Rabin test
(defun probably-prime-p (n trials)
  (let ((d (1- n))
        (s 0))
    ;; write n - 1 = 2^s * d
    (loop while (evenp d)
          do (setf d (/ d 2))
             (incf s))
    (loop repeat trials
          for a = (+ 2 (random (- n 4))) ; random base in [2, n-2]
          for x = (mod-exp a d n)
          unless (or (= x 1) (= x (1- n)))
            do (loop repeat (1- s)
                     do (setf x (mod-exp x 2 n))
                        (when (= x (1- n)) (return))
                     finally (return-from probably-prime-p nil))
          finally (return t))))

(defun generate-prime (bits &optional (trials 5))
  (loop
    for candidate = (random-odd-bignum bits)
    when (probably-prime-p candidate trials)
	return candidate))
