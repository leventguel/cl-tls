(defpackage :sha224
  (:use :cl :shared-utils :sha-utils)
  (:export :sha224 :sha224-hex))

(in-package :sha224)

(defun sigma0 (x) (logxor (rotr32 x 2) (rotr32 x 13) (rotr32 x 22)))
(defun sigma1 (x) (logxor (rotr32 x 6) (rotr32 x 11) (rotr32 x 25)))
(defun gamma0 (x) (logxor (rotr32 x 7) (rotr32 x 18) (shr32 x 3)))
(defun gamma1 (x) (logxor (rotr32 x 17) (rotr32 x 19) (shr32 x 10)))

(defparameter +h0-224+
  #( #xc1059ed8 #x367cd507 #x3070dd17 #xf70e5939
     #xffc00b31 #x68581511 #x64f98fa7 #xbefa4fa4 ))

(defparameter +k-224+
  #( #x428a2f98 #x71374491 #xb5c0fbcf #xe9b5dba5 #x3956c25b #x59f111f1 #x923f82a4 #xab1c5ed5
     #xd807aa98 #x12835b01 #x243185be #x550c7dc3 #x72be5d74 #x80deb1fe #x9bdc06a7 #xc19bf174
     #xe49b69c1 #xefbe4786 #x0fc19dc6 #x240ca1cc #x2de92c6f #x4a7484aa #x5cb0a9dc #x76f988da
     #x983e5152 #xa831c66d #xb00327c8 #xbf597fc7 #xc6e00bf3 #xd5a79147 #x06ca6351 #x14292967
     #x27b70a85 #x2e1b2138 #x4d2c6dfc #x53380d13 #x650a7354 #x766a0abb #x81c2c92e #x92722c85
     #xa2bfe8a1 #xa81a664b #xc24b8b70 #xc76c51a3 #xd192e819 #xd6990624 #xf40e3585 #x106aa070
     #x19a4c116 #x1e376c08 #x2748774c #x34b0bcb5 #x391c0cb3 #x4ed8aa4a #x5b9cca4f #x682e6ff3
     #x748f82ee #x78a5636f #x84c87814 #x8cc70208 #x90befffa #xa4506ceb #xbef9a3f7 #xc67178f2 ))

(defun sha224-pad (message)
  (let* ((ml (* (length message) 8))
         (padlen (mod (- 448 (mod (+ ml 8) 512)) 512))
         (total (+ ml 8 padlen 64))
         (bytes (/ total 8))
         (padded (make-array bytes :element-type '(unsigned-byte 8) :initial-element 0)))
    (replace padded message)
    (setf (aref padded (length message)) #x80)
    (loop for i from 0 below 8
          for shift = (* 8 (- 7 i))
          do (setf (aref padded (+ (- bytes 8) i))
                   (ldb (byte 8 shift) ml)))
    (loop for i from 0 below bytes by 64
          collect (subseq padded i (+ i 64)))))

(defun sha224-schedule (block)
  (let ((w (make-array 64 :element-type '(unsigned-byte 32))))
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
    (loop for i from 16 below 64
          do (setf (aref w i)
                   (mod (+ (gamma1 (aref w (- i 2)))
                           (aref w (- i 7))
                           (gamma0 (aref w (- i 15)))
                           (aref w (- i 16)))
                        #x100000000)))
    w))

(defun sha224-compress (w h)
  (let ((a (aref h 0)) (b (aref h 1)) (c (aref h 2)) (d (aref h 3))
        (e (aref h 4)) (f (aref h 5)) (g (aref h 6)) (h0 (aref h 7)))
    (loop for i from 0 below 64
          for t1 = (mod (+ h0 (sigma1 e) (ch e f g) (aref +k-224+ i) (aref w i)) #x100000000)
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
    (let ((new-h (make-array 8 :element-type '(unsigned-byte 32)))) ;; we can use 32 here since 224 < 256
      (loop for i from 0 below 8
            for val in (list a b c d e f g h0)
            do (setf (aref new-h i)
                     (mod (+ (aref h i) val) #x100000000)))
      new-h)))

(defun sha224 (message)
  (let ((blocks (sha224-pad message))
        (h (copy-seq +h0-224+)))
    (dolist (block blocks)
      (let ((w (sha224-schedule block)))
        (setf h (sha224-compress w h))))
    ;; Return only the first 7 words (224 bits) (from 8*32 = 256)
    (subseq h 0 7)))

(defun sha224-hex (message)
  (let ((digest (sha224 message)))
    (string-downcase
     (with-output-to-string (s)
       (loop for word across digest
             do (loop for shift from 24 downto 0 by 8
                      do (format s "~2,'0X" (ldb (byte 8 shift) word))))))))

(format t "~a~%" (sha224-hex (map 'vector #'char-code "abc")))
