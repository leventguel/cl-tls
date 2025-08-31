(defpackage :sha512
  (:use :cl :shared-utils :sha-utils)
  (:export :sha512 :sha512-hex))

(in-package :sha512)

(defun sigma0-64 (x) (logxor (rotr64 x 28) (rotr64 x 34) (rotr64 x 39)))
(defun sigma1-64 (x) (logxor (rotr64 x 14) (rotr64 x 18) (rotr64 x 41)))
(defun gamma0-64 (x) (logxor (rotr64 x 1) (rotr64 x 8) (shr64 x 7)))
(defun gamma1-64 (x) (logxor (rotr64 x 19) (rotr64 x 61) (shr64 x 6)))

(defparameter +h0-512+
  #(#x6a09e667f3bcc908
    #xbb67ae8584caa73b
    #x3c6ef372fe94f82b
    #xa54ff53a5f1d36f1
    #x510e527fade682d1
    #x9b05688c2b3e6c1f
    #x1f83d9abfb41bd6b
    #x5be0cd19137e2179))

(defparameter +k-512+
  #(#x428a2f98d728ae22 #x7137449123ef65cd #xb5c0fbcfec4d3b2f #xe9b5dba58189dbbc
    #x3956c25bf348b538 #x59f111f1b605d019 #x923f82a4af194f9b #xab1c5ed5da6d8118
    #xd807aa98a3030242 #x12835b0145706fbe #x243185be4ee4b28c #x550c7dc3d5ffb4e2
    #x72be5d74f27b896f #x80deb1fe3b1696b1 #x9bdc06a725c71235 #xc19bf174cf692694
    #xe49b69c19ef14ad2 #xefbe4786384f25e3 #x0fc19dc68b8cd5b5 #x240ca1cc77ac9c65
    #x2de92c6f592b0275 #x4a7484aa6ea6e483 #x5cb0a9dcbd41fbd4 #x76f988da831153b5
    #x983e5152ee66dfab #xa831c66d2db43210 #xb00327c898fb213f #xbf597fc7beef0ee4
    #xc6e00bf33da88fc2 #xd5a79147930aa725 #x06ca6351e003826f #x142929670a0e6e70
    #x27b70a8546d22ffc #x2e1b21385c26c926 #x4d2c6dfc5ac42aed #x53380d139d95b3df
    #x650a73548baf63de #x766a0abb3c77b2a8 #x81c2c92e47edaee6 #x92722c851482353b
    #xa2bfe8a14cf10364 #xa81a664bbc423001 #xc24b8b70d0f89791 #xc76c51a30654be30
    #xd192e819d6ef5218 #xd69906245565a910 #xf40e35855771202a #x106aa07032bbd1b8
    #x19a4c116b8d2d0c8 #x1e376c085141ab53 #x2748774cdf8eeb99 #x34b0bcb5e19b48a8
    #x391c0cb3c5c95a63 #x4ed8aa4ae3418acb #x5b9cca4f7763e373 #x682e6ff3d6b2b8a3
    #x748f82ee5defb2fc #x78a5636f43172f60 #x84c87814a1f0ab72 #x8cc702081a6439ec
    #x90befffa23631e28 #xa4506cebde82bde9 #xbef9a3f7b2c67915 #xc67178f2e372532b
    #xca273eceea26619c #xd186b8c721c0c207 #xeada7dd6cde0eb1e #xf57d4f7fee6ed178
    #x06f067aa72176fba #x0a637dc5a2c898a6 #x113f9804bef90dae #x1b710b35131c471b
    #x28db77f523047d84 #x32caab7b40c72493 #x3c9ebe0a15c9bebc #x431d67c49c100d4c
    #x4cc5d4becb3e42b6 #x597f299cfc657e2a #x5fcb6fab3ad6faec #x6c44198c4a475817))

(defun sha512-pad (message)
  (let* ((ml (* (length message) 8)) ; message length in bits
         (padlen (mod (- 896 (mod (+ ml 8) 1024)) 1024)) ; bits of zero-padding
         (total (+ ml 8 padlen 128)) ; total bits after padding
         (bytes (/ total 8))
         (padded (make-array bytes :element-type '(unsigned-byte 8) :initial-element 0)))
    ;; Copy original message
    (replace padded message)
    ;; Append 0x80 (10000000)
    (setf (aref padded (length message)) #x80)
    ;; Append 128-bit big-endian length (we only support messages < 2^64 bits)
    ;; So high 64 bits are zero
    (loop for i from 0 below 8
          do (setf (aref padded (+ (- bytes 16) i)) 0))
    (loop for i from 0 below 8
          for shift = (* 8 (- 7 i))
          do (setf (aref padded (+ (- bytes 8) i))
                   (ldb (byte 8 shift) ml)))
    ;; Return list of 128-byte blocks
    (loop for i from 0 below bytes by 128
          collect (subseq padded i (+ i 128)))))

(defun sha512-schedule (block)
  (let ((w (make-array 80 :element-type '(unsigned-byte 64))))
    ;; First 16 words from the block
    (loop for i from 0 below 16
          for j = (* i 8)
          do (setf (aref w i)
                   (logior (ash (aref block j) 56)
                           (ash (aref block (+ j 1)) 48)
                           (ash (aref block (+ j 2)) 40)
                           (ash (aref block (+ j 3)) 32)
                           (ash (aref block (+ j 4)) 24)
                           (ash (aref block (+ j 5)) 16)
                           (ash (aref block (+ j 6)) 8)
                           (aref block (+ j 7)))))
    ;; Expand to 80 words
    (loop for i from 16 below 80
          do (setf (aref w i)
                   (mod (+ (gamma1-64 (aref w (- i 2)))
                           (aref w (- i 7))
                           (gamma0-64 (aref w (- i 15)))
                           (aref w (- i 16)))
                        #x10000000000000000)))
    w))

(defun sha512-compress (w h)
  (let ((a (aref h 0)) (b (aref h 1)) (c (aref h 2)) (d (aref h 3))
        (e (aref h 4)) (f (aref h 5)) (g (aref h 6)) (h0 (aref h 7)))
    (loop for i from 0 below 80
          for t1 = (mod (+ h0
                           (sigma1-64 e)
                           (ch e f g)
                           (aref +k-512+ i)
                           (aref w i))
                        #x10000000000000000)
          for t2 = (mod (+ (sigma0-64 a)
                           (maj a b c))
                        #x10000000000000000)
          do (let ((new-a (mod (+ t1 t2) #x10000000000000000))
                   (new-e (mod (+ d t1) #x10000000000000000)))
               (setf h0 g
                     g f
                     f e
                     e new-e
                     d c
                     c b
                     b a
                     a new-a)))
    ;; Compute new hash state
    (let ((new-h (make-array 8 :element-type '(unsigned-byte 64))))
      (loop for i from 0 below 8
            for val in (list a b c d e f g h0)
            do (setf (aref new-h i)
                     (mod (+ (aref h i) val) #x10000000000000000)))
      new-h)))

(defun sha512 (message)
  (let ((blocks (sha512-pad message))
        (h (copy-seq +h0-512+)))
    (dolist (block blocks)
      (let ((w (sha512-schedule block)))
        (setf h (sha512-compress w h))))
    h)) ; returns vector of 8 64-bit words (512bits)

(defun sha512-hex (message)
  (let ((digest (sha512 message)))
    (string-downcase
     (with-output-to-string (s)
       (loop for word across digest
             do (loop for shift from 56 downto 0 by 8
                      do (format s "~2,'0X" (ldb (byte 8 shift) word))))))))

(format t "~a~%" (sha512-hex (map 'vector #'char-code "abc")))
