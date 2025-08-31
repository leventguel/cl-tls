(defpackage :sha1
  (:use :cl :shared-utils :sha-utils)
  (:export :sha1 :sha1-hex))

(in-package :sha1)

(defun sigma0 (x) (logxor (rotl32 x 2) (rotl32 x 13) (rotl32 x 22)))
(defun sigma1 (x) (logxor (rotl32 x 6) (rotl32 x 11) (rotl32 x 25)))
(defun gamma0 (x) (logxor (rotl32 x 7) (rotl32 x 18) (shr32 x 3)))
(defun gamma1 (x) (logxor (rotl32 x 17) (rotl32 x 19) (shr32 x 10)))

(defparameter +h0-160+ #(#x67452301 #xefcdab89 #x98badcfe #x10325476 #xc3d2e1f0))
(defparameter +k-sha1+ #(#x5a827999 #x6ed9eba1 #x8f1bbcdc #xca62c1d6))

(defun sha1-pad (message)
  (let* ((ml (* (length message) 8)) ; message length in bits
         (padlen (mod (- 448 (mod (+ ml 8) 512)) 512)) ; bits of zero-padding
         (total (+ ml 8 padlen 64)) ; total bits
         (bytes (/ total 8))
         (padded (make-array bytes :element-type '(unsigned-byte 8) :initial-element 0)))
    ;; Copy original message
    (replace padded message)
    ;; Append 0x80 (10000000)
    (setf (aref padded (length message)) #x80)
    ;; Append 64-bit big-endian length
		(loop for i from 0 below 8
      for shift = (* 8 (- 7 i))
      do (setf (aref padded (+ (- bytes 8) i))
               (ldb (byte 8 shift) ml)))    
    ;; Return list of 64-byte blocks
    (loop for i from 0 below bytes by 64
          collect (subseq padded i (+ i 64)))))

(defun sha1-schedule (block)
  (let ((w (make-array 80 :element-type '(unsigned-byte 32))))
    (loop for i from 0 below 16
          for j = (* i 4)
          do (setf (aref w i)
                   (logior (ash (aref block j) 24)
                           (ash (aref block (+ j 1)) 16)
                           (ash (aref block (+ j 2)) 8)
                           (aref block (+ j 3)))))
    (loop for i from 16 below 80
          do (setf (aref w i)
                   (rotl32 (logxor (aref w (- i 3))
                                   (aref w (- i 8))
                                   (aref w (- i 14))
                                   (aref w (- i 16)))
                           1)))
    w))

(defun sha1-compress (w h)
  (let ((a (aref h 0)) (b (aref h 1)) (c (aref h 2))
        (d (aref h 3)) (e (aref h 4)))
    (loop for i from 0 below 80
          for f = (cond ((< i 20) (logior (logand b c) (logand (lognot b) d)))
                        ((< i 40) (logxor b c d))
                        ((< i 60) (logior (logand b c) (logand b d) (logand c d)))
                        (t (logxor b c d)))
          for k = (cond ((< i 20) (aref +k-sha1+ 0))
                        ((< i 40) (aref +k-sha1+ 1))
                        ((< i 60) (aref +k-sha1+ 2))
                        (t (aref +k-sha1+ 3)))
          for temp = (mod (+ (rotl32 a 5) f e k (aref w i)) #x100000000)
          do (setf e d
                   d c
                   c (rotl32 b 30)
                   b a
                   a temp))
    (let ((new-h (make-array 5 :element-type '(unsigned-byte 32))))
      (loop for i from 0 below 5
            for val in (list a b c d e)
            do (setf (aref new-h i)
                     (mod (+ (aref h i) val) #x100000000)))
      new-h)))

(defun sha1 (message)
  (let ((blocks (sha1-pad message))
        (h (copy-seq +h0-160+)))
    (dolist (block blocks)
      (let ((w (sha1-schedule block)))
        (setf h (sha1-compress w h))))
    h))

(defun sha1-hex (message)
  (let ((digest (sha1 message)))
    (string-downcase
     (with-output-to-string (s)
       (loop for word across digest
             do (loop for shift from 24 downto 0 by 8
                      do (format s "~2,'0X" (ldb (byte 8 shift) word))))))))

(defun sha1-bytes (message) (words-to-bytes (sha1 message)))
(defun sha1-digest-hex (message) (bytes-to-hex (sha1-bytes message)))

(format t "~a~%" (sha1-hex (map 'vector #'char-code "abc")))
;; Should return: a9993e364706816aba3e25717850c26c9cd0d89d
