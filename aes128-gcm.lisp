(defpackage :tls-aes128-gcm
  (:use :cl :tls-aes-utils :tls-aes-ghash :tls-aes128)
  (:export :aes128-gcm-encrypt :aes128-gcm-decrypt))

(in-package :tls-aes128-gcm)

(defun hex-string-to-byte-vector (hex)
  "Converts a hex string to a vector of unsigned bytes. Ignores whitespace."
  (let* ((clean (remove-if (lambda (ch) (find ch " \t\n\r")) hex))
         (n (length clean))
         (length-bytes (floor n 2))
         (bytes (make-array length-bytes :element-type '(unsigned-byte 8))))
    (unless (zerop (mod (length clean) 2))
      (error "Hex string must contain an even number of characters"))
    (loop for i from 0 below length-bytes do
      (setf (aref bytes i)
            (parse-integer clean :start (* i 2) :end (+ (* i 2) 2) :radix 16)))
    bytes))

(defun byte-vector-to-hex-string (vec)
  (format nil "~{~2,'0X~}" (coerce vec 'list)))

(defun byte-vector-to-integer (bytes)
  "Convert a vector of unsigned 8-bit bytes (big-endian) into an integer."
  (check-type bytes (vector (unsigned-byte 8)))
  (reduce (lambda (acc byte)
            (+ (* acc 256) byte))
          bytes
          :initial-value 0))

(defun integer-to-byte-vector (n size)
  "Convert integer N to a vector of unsigned 8-bit bytes (big-endian).                                                  
   Pads or truncates to SIZE bytes."
  (check-type n integer)
  (check-type size integer)
  (let ((bytes (make-array size :element-type '(unsigned-byte 8))))
    (dotimes (i size)
      (setf (aref bytes (- size i 1)) (logand #xFF (ash n (- (* i 8))))))
    bytes))

(defun pad-blocks (bytes)
  "Pads input to 16-byte block boundary."
  (let* ((len (length bytes))
         (pad-len (mod (- 16 (mod len 16)) 16))
         (full (concatenate '(vector (unsigned-byte 8)) bytes
                            (make-array pad-len :element-type '(unsigned-byte 8)
                                        :initial-element 0)))
         (blocks '()))
    (loop for i from 0 below (length full) by 16
          do (push (subseq full i (+ i 16)) blocks))
    (nreverse blocks)))

#|
(defun length-block (aad-len ct-len)
  "Returns a 16-byte block with 64-bit big-endian lengths of AAD and CT."
  (concatenate '(vector (unsigned-byte 8))
               (int->block-64be (* 8 aad-len))
               (int->block-64be (* 8 ct-len))))
|#
(defun length-block (aad-len-in-bits ct-len-in-bits)
  (concatenate '(vector (unsigned-byte 8))
               (int->block-64be aad-len-in-bits)
               (int->block-64be ct-len-in-bits)))

(defun build-ghash-blocks (aad ct &optional aad-len ct-len)
  "Returns list of padded blocks and final length block. Lengths in bytes."
  (let ((aad-len (or aad-len (length aad)))
        (ct-len (or ct-len (length ct))))
    (append (pad-blocks aad)
            (pad-blocks ct)
            (list (length-block (* 8 aad-len) (* 8 ct-len))))))

(defun inc-counter (ctr)
  "Increment the last 32 bits (bytes 12–15) of the 16-byte counter block, big-endian."
  (check-type ctr (vector (unsigned-byte 8)))
  (assert (= (length ctr) 16) () "Counter block must be 16 bytes.")
  (let* ((prefix (subseq ctr 0 12))
         (suffix (subseq ctr 12 16))
         (ctr-val (byte-vector-to-integer suffix)) ;; big-endian                                                        
         (new-val (mod (+ ctr-val 1) (expt 2 32)))
         (new-suffix (integer-to-byte-vector new-val 4))) ;; big-endian                                                 
    (concatenate '(vector (unsigned-byte 8)) prefix new-suffix)))

(defun chunk-blocks (vec &optional (block-size 16))
  "Splits a vector into a list of block-size chunks."
  (loop for i from 0 below (length vec) by block-size
        collect (subseq vec i (min (length vec) (+ i block-size)))))

(defun chunk-all (vec &optional (size 16))
  (loop for i from 0 below (length vec) by size
        collect (subseq vec i (min (+ i size) (length vec)))))

(defun gctr (key icb plaintext)
  (let ((blocks (chunk-all plaintext))
        (out '()))
    (loop for blk in blocks
          for ctr = (inc-counter icb) then (inc-counter ctr)
          for ek = (aes128-ecb-encrypt ctr key t nil)
          collect (map 'vector #'logxor ek blk) into out
          finally (return (apply #'concatenate '(vector (unsigned-byte 8)) out)))))

(defun truncate-tag (tag bits)
  (subseq tag 0 (/ bits 8)))

(defun aes128-gcm-encrypt (plaintext key iv &optional (aad #()) (taglen 128) (aad-len 0) (ctlen 0))
  "Encrypts plaintext using AES-GCM. Returns (ciphertext truncated-tag)."
  (let* ((expanded-key
          (cond ((= (length key) 16) (expand-key-128 key))
                (t (error "Invalid AES key length: ~D" (length key)))))
         (h (aes128-ecb-encrypt (make-array 16 :element-type '(unsigned-byte 8)
                                            :initial-element 0)
                                expanded-key t nil))
	 (iv-bitlen (* (length iv) 8))
	 (j0 (if (= iv-bitlen 96) (concatenate '(vector (unsigned-byte 8)) iv #(#x0 #x0 #x0 #x01))
		 (let ((len-block (concatenate '(vector (unsigned-byte 8))
					       (int->block-64be 0) ;; aad must be 0 here!
					       (int->block-64be iv-bitlen)))) ;; iv
		   (ghash h (append (pad-blocks iv) (list len-block))))))
         (init-counter (copy-seq j0)))

    (let* ((ciphertext (gctr expanded-key init-counter plaintext))
	   (aad-len (length aad))
	   (ctlen (length ciphertext))
	   (len-block (concatenate '(vector (unsigned-byte 8))
				   (int->block-64be (* aad-len 8)) ;; bitlen of AAD here
				   (int->block-64be (* ctlen 8)))) ;; bitlen of CT here
	   (ghash-in (append (pad-blocks aad) (pad-blocks ciphertext) (list len-block)))
           ;;(ghash-in (build-ghash-blocks aad ciphertext aad-len ctlen))
           (s (ghash h ghash-in))
           (tag-base (aes128-ecb-encrypt j0 expanded-key t nil))
           (full-tag (make-array 16 :element-type '(unsigned-byte 8))))

      (when (< iv-bitlen 64)
	(warn "IV too short — may weaken GCM security"))
      
      (when (> iv-bitlen 16384)
	(warn "Unusually long IV — GHASH performance may degrade"))
      
      (format t "~%Tag base: ~X" (byte-vector-to-hex-string tag-base))
      (format t "~%GHASH result (s): ~X" (byte-vector-to-hex-string s))
      (mapc (lambda (blk) (format t "~%GHASH block: ~X" blk)) ghash-in)
      (dotimes (i (length full-tag))
        (setf (aref full-tag i) (logxor (aref tag-base i) (aref s i))))
      (format t "~%Ciphertext: ~X" (byte-vector-to-hex-string ciphertext))
      (format t "~%Full TAG: ~X" (byte-vector-to-hex-string full-tag))
      (values ciphertext (truncate-tag full-tag taglen)))))

(defun aes128-gcm-decrypt (ciphertext key iv tag &optional (aad #()) (taglen 128) (aad-len 0) (ctlen 0))
  "Decrypts AES-GCM ciphertext. Returns plaintext if tag verifies, else error."
  (let* ((expanded-key
          (cond ((= (length key) 16) (expand-key-128 key))
                (t (error "Invalid AES key length: ~D" (length key)))))
         (h (aes128-ecb-encrypt (make-array 16 :element-type '(unsigned-byte 8)
                                            :initial-element 0)
                                expanded-key t nil))
	 (iv-bitlen (* (length iv) 8))
	 (j0 (if (= iv-bitlen 96) (concatenate '(vector (unsigned-byte 8)) iv #(#x0 #x0 #x0 #x01))
		 (let ((len-block (concatenate '(vector (unsigned-byte 8))
					       (int->block-64be 0) ;; aad must be 0 here!
					       (int->block-64be iv-bitlen)))) ;; iv part
		   (ghash h (append (pad-blocks iv) (list len-block))))))
         (init-counter (copy-seq j0)))

    (let* ((plaintext (gctr expanded-key init-counter ciphertext))
	   (aad-len (length aad))
	   (ctlen (length ciphertext))
	   (len-block (concatenate '(vector (unsigned-byte 8))
				   (int->block-64be (* aad-len 8)) ;; bitlen of AAD 160 here
				   (int->block-64be (* ctlen 8)))) ;; bitlen of CT 256 here
	   (ghash-in (append (pad-blocks aad) (pad-blocks ciphertext) (list len-block)))
           ;;(ghash-in (build-ghash-blocks aad ciphertext aad-len ctlen))
           (s (ghash h ghash-in))
           (tag-base (aes128-ecb-encrypt j0 expanded-key t nil))
           (full-tag (make-array 16 :element-type '(unsigned-byte 8))))

      (when (< iv-bitlen 64)
	(warn "IV too short — may weaken GCM security"))
      
      (when (> iv-bitlen 16384)
	(warn "Unusually long IV — GHASH performance may degrade"))
      
      (dotimes (i 16)
        (setf (aref full-tag i) (logxor (aref tag-base i) (aref s i))))
      (if (equalp tag (truncate-tag full-tag taglen))
          plaintext
          (error "Invalid authentication tag")))))
