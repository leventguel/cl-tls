(defpackage :hmac-sha1
  (:use :cl :tls-utils :sha1)
  (:export :hmac-sha1))

(in-package :hmac-sha1)

(defun rotr32 (x n)
  (mod (logior (ash x (- n))
               (ash x (- 32 n)))
       #x100000000))

(defun rotl32 (x n)
  (mod (logior (ash x n)
               (ash x (- n 32)))
       #x100000000))

(defun shr32 (x n)
  (mod (ash x (- n)) #x100000000))

(defun ch (x y z) (logxor (logand x y) (logand (lognot x) z)))
(defun maj (x y z) (logxor (logand x y) (logand x z) (logand y z)))
(defun sigma0 (x) (logxor (rotl32 x 2) (rotl32 x 13) (rotl32 x 22)))
(defun sigma1 (x) (logxor (rotl32 x 6) (rotl32 x 11) (rotl32 x 25)))
(defun gamma0 (x) (logxor (rotl32 x 7) (rotl32 x 18) (shr32 x 3)))
(defun gamma1 (x) (logxor (rotl32 x 17) (rotl32 x 19) (shr32 x 10)))

(defparameter +h0-160+
  #( #x67452301 #xefcdab89 #x98badcfe #x10325476 #xc3d2e1f0 ))

(defparameter +k-sha1+
  #( #x5a827999 #x6ed9eba1 #x8f1bbcdc #xca62c1d6 ))

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

(defun words-to-bytes (words)
  (let ((bytes (make-array (* 4 (length words)) :element-type '(unsigned-byte 8))))
    (loop for i from 0 below (length words)
          for word = (aref words i)
          for base = (* i 4)
          do (setf (aref bytes base)       (ldb (byte 8 24) word)
                   (aref bytes (+ base 1)) (ldb (byte 8 16) word)
                   (aref bytes (+ base 2)) (ldb (byte 8 8) word)
                   (aref bytes (+ base 3)) (ldb (byte 8 0) word)))
    bytes))

(defun bytes-to-hex (bytes)
  (with-output-to-string (s)
    (loop for b across bytes
          do (format s "~2,'0X" b))))

(defun sha1-bytes (message) (words-to-bytes (sha1 message)))
(defun sha1-hex (message) (bytes-to-hex (sha1-bytes message)))

(defun hmac-sha1 (key message)
  (let* ((block-size 64)
         (key (if (> (length key) block-size)
                  (words-to-bytes (sha1 key))
                  key))
         (key (concatenate '(vector (unsigned-byte 8))
                           key
                           (make-array (- block-size (length key))
                                       :element-type '(unsigned-byte 8)
                                       :initial-element 0)))
         (ipad (make-array block-size :element-type '(unsigned-byte 8)
                                      :initial-element #x36))
         (opad (make-array block-size :element-type '(unsigned-byte 8)
                                      :initial-element #x5c)))
    (loop for i from 0 below block-size do
      (setf (aref ipad i) (logxor (aref ipad i) (aref key i))
            (aref opad i) (logxor (aref opad i) (aref key i))))
    (words-to-bytes
     (sha1
      (concatenate '(vector (unsigned-byte 8))
                   opad
                   (words-to-bytes
                    (sha1
                     (concatenate '(vector (unsigned-byte 8))
                                  ipad
                                  message))))))))

(let ((key (make-array 20 :element-type '(unsigned-byte 8) :initial-element #x0b))
      (msg (map 'vector #'char-code "Hi There")))
  (format t "HMAC-SHA256: ~A~%"
          (string-downcase (bytes-to-hex (hmac-sha1 key msg)))))
