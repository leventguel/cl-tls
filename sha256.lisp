(defpackage :sha256
  (:use :cl :shared-utils :sha-utils)
  (:export :sha256 :sha256-hex))

(in-package :sha256)

(defun sigma0 (x) (logxor (rotr32 x 2) (rotr32 x 13) (rotr32 x 22)))
(defun sigma1 (x) (logxor (rotr32 x 6) (rotr32 x 11) (rotr32 x 25)))
(defun gamma0 (x) (logxor (rotr32 x 7) (rotr32 x 18) (shr32 x 3)))
(defun gamma1 (x) (logxor (rotr32 x 17) (rotr32 x 19) (shr32 x 10)))

(defparameter +h0-256+
  #( #x6a09e667 #xbb67ae85 #x3c6ef372 #xa54ff53a
    #x510e527f #x9b05688c #x1f83d9ab #x5be0cd19 ))

(defparameter +k-256+
  #( #x428a2f98 #x71374491 #xb5c0fbcf #xe9b5dba5 #x3956c25b #x59f111f1 #x923f82a4 #xab1c5ed5
    #xd807aa98 #x12835b01 #x243185be #x550c7dc3 #x72be5d74 #x80deb1fe #x9bdc06a7 #xc19bf174
    #xe49b69c1 #xefbe4786 #x0fc19dc6 #x240ca1cc #x2de92c6f #x4a7484aa #x5cb0a9dc #x76f988da
    #x983e5152 #xa831c66d #xb00327c8 #xbf597fc7 #xc6e00bf3 #xd5a79147 #x06ca6351 #x14292967
    #x27b70a85 #x2e1b2138 #x4d2c6dfc #x53380d13 #x650a7354 #x766a0abb #x81c2c92e #x92722c85
    #xa2bfe8a1 #xa81a664b #xc24b8b70 #xc76c51a3 #xd192e819 #xd6990624 #xf40e3585 #x106aa070
    #x19a4c116 #x1e376c08 #x2748774c #x34b0bcb5 #x391c0cb3 #x4ed8aa4a #x5b9cca4f #x682e6ff3
    #x748f82ee #x78a5636f #x84c87814 #x8cc70208 #x90befffa #xa4506ceb #xbef9a3f7 #xc67178f2 ))

(defun sha256-pad (message)
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

(defun sha256-schedule (block)
  (let ((w (make-array 64 :element-type '(unsigned-byte 32))))
    ;; W[0..15] from block (big-endian)
    (loop for i from 0 below 16
          for j = (* i 4)
          for a = (aref block j)
          for b = (aref block (+ j 1))
          for c = (aref block (+ j 2))
          for d = (aref block (+ j 3))
          do (setf (aref w i)
                   (mod (logior (logior (logior (ash a 24)
                                                (ash b 16))
                                        (ash c 8))
                                d)
                        #x100000000)))
    ;; W[16..63] expansion
    (loop for i from 16 below 64
          do (setf (aref w i)
                   (mod (+ (gamma1 (aref w (- i 2)))
                           (aref w (- i 7))
                           (gamma0 (aref w (- i 15)))
                           (aref w (- i 16)))
                        #x100000000)))
    w))

(defun sha256-compress (w h)
  (let ((a (aref h 0)) (b (aref h 1)) (c (aref h 2)) (d (aref h 3))
        (e (aref h 4)) (f (aref h 5)) (g (aref h 6)) (h0 (aref h 7)))
    (loop for i from 0 below 64
          for t1 = (mod (+ h0 (sigma1 e) (ch e f g) (aref +k-256+ i) (aref w i)) #x100000000)
          for t2 = (mod (+ (sigma0 a) (maj a b c)) #x100000000)
          do (let ((new-a (mod (+ t1 t2) #x100000000))
                   (new-e (mod (+ d t1) #x100000000)))
               (setf h0 g
                     g f
                     f e
                     e new-e
                     d c
                     c b
                     b a
                     a new-a)))
    (let ((new-h (make-array 8 :element-type '(unsigned-byte 32))))
      (loop for i from 0 below 8
            for val in (list a b c d e f g h0)
            do (setf (aref new-h i)
                     (mod (+ (aref h i) val) #x100000000)))
      new-h)))

(defun sha256 (message)
  (let ((blocks (sha256-pad message))
        (h (copy-seq +h0-256+)))
    (dolist (block blocks)
      (let ((w (sha256-schedule block)))
        (setf h (sha256-compress w h))))
    (subseq h 0 8)))

(defun sha256-hex (message)
  (let ((digest (sha256 message)))
    (string-downcase (with-output-to-string (s)
		       (loop for word across digest
			     do (loop for shift from 24 downto 0 by 8
				      do (format s "~2,'0X" (ldb (byte 8 shift) word))))))))

(format t "~a~%" (sha256-hex (map 'vector #'char-code "abc")))
