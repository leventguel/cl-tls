(in-package :tls-aes128)

(defun inc-counter (block)
  "Increment last 32 bits of 16-byte vector as a big-endian counter."
  (let ((out (copy-seq block)))
    (loop for i from 15 downto 12 do
      (setf (aref out i)
            (ldb (byte 8 0)
                 (+ (aref out i)
                    (if (= i 15) 1 0))))
      (when (< (aref out i) 256)
	(return)))
    out))

(defun block->int (block)
  (loop with acc = 0
        for b across block
        do (setf acc (logior (ash acc 8) b))
        finally (return acc)))

(defun int->block (int)
  (let ((block (make-array 16 :element-type '(unsigned-byte 8))))
    (dotimes (i 16)
      (setf (aref block i) (ldb (byte 8 (* 8 (- 15 i))) int)))
    block))

(defun int->block-le (i)
  "Convert 128-bit integer to 16-byte little-endian vector."
  (let ((out (make-array 16 :element-type '(unsigned-byte 8))))
    (loop for idx from 0 below 16 do
      (setf (aref out idx) (ldb (byte 8 0) i))
      (setf i (ash i -8)))
    out))

(defun block->int-le (bytes)
  "Convert 16-byte vector to integer (little-endian)."
  (reduce (lambda (acc b) (logior (ash acc 8) b))
          (reverse bytes)
          :initial-value 0))

(defun int->block-64be (int)
  (let ((block (make-array 8 :element-type '(unsigned-byte 8))))
    (dotimes (i 8)
      (setf (aref block i) (ldb (byte 8 (* 8 (- 7 i))) int)))
    block))

(defun chunk-blocks (vec &optional (block-size 16))
  "Splits a vector into a list of block-size chunks."
  (loop for i from 0 below (length vec) by block-size
	collect (subseq vec i (min (length vec) (+ i block-size)))))

(defun gf128-mul (x y)
  (let ((res 0)
        (R #xE1000000000000000000000000000000)
        (mask #xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF))
    (dotimes (i 128)
      (when (logbitp (- 127 i) y)
        (setf res (logxor res x)))
      (setf res (logand res mask)) ;; ✨ constrain res to 128 bits
      (setf x (if (logbitp 0 x)
		  (logand (logxor (ash x -1) R) mask)
                  (logand (ash x -1) mask)))
      (setf x (logand x mask)))
    res))

(defun ghash (h blocks)
  (let ((h-int (block->int h))
	(y 0))
    (dolist (block blocks)
      (setf y (gf128-mul h-int (logxor y (block->int block)))))
    (int->block y)))

(defun gctr (key icb plaintext)
  (let ((blocks (chunk-blocks plaintext))
        (out '()))
    (loop for blk in blocks
          for ctr = (inc-counter icb) then (inc-counter ctr)
          for ek = (aes128-ecb-encrypt ctr key t nil)
          collect (map 'vector #'logxor ek blk) into out
          finally (return (apply #'concatenate '(vector (unsigned-byte 8)) out)))))

(let* (;; NIST AES-GCM Encrypt Test 0
       (key (hex-string-to-byte-vector "7fddb57453c241d03efbed3ac44e371c"))
       (iv  (hex-string-to-byte-vector "ee283a3fc75575e33efd4887"))
       (aad (hex-string-to-byte-vector ""))
       (pt (hex-string-to-byte-vector "d5de42b461646c255c87bd2962d3b9a2"))
       (ct (hex-string-to-byte-vector "2ccda4a5415cb91e135c2a0f78c9b2fd"))

       ;; Expanded key and subkey H
       (expanded-key (expand-key-128 key))
       (h (aes128-ecb-encrypt
           (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)
           expanded-key t nil))

       ;; Construct J₀
       (j0 (concatenate '(vector (unsigned-byte 8)) iv #(#x0 #x0 #x0 #x01)))

       ;; Encrypt plaintext using AES-CTR (J₀ + 1)
       ;; Note: PT is only one block here
       (ct (gctr expanded-key j0 pt))

       ;; GHASH input blocks: AAD + length
       ;; 0 AAD bits, 128 CT bits
       (len-block (concatenate '(vector (unsigned-byte 8))
                              (int->block-64be 0)      ; bitlen of AAD
                              (int->block-64be 128)))
       (ghash-input (append (chunk-blocks aad) (chunk-blocks ct) (list len-block)))

       ;; Compute GHASH digest
       (s (ghash h ghash-input))

       ;; Compute tag base
       (tag-base (aes128-ecb-encrypt j0 expanded-key t nil))

       ;; Compute final tag
       (computed-tag (coerce (loop for i below 16
			   collect (logxor (aref tag-base i) (aref s i))) 'vector))

       ;; Expected tag (from NIST test vector)
       (expected-tag (hex-string-to-byte-vector "b36d1df9b9d5e596f83e8b7f52971cb3")))

  ;; Output comparison
  (format t "~%🧪 GHASH blocks:~%")
  (loop for blk in ghash-input
        for idx from 0
        do (format t "  Block ~D: ~X~%" idx (byte-vector-to-hex-string blk)))

  (format t "~%🔐 H subkey: ~X~%" (byte-vector-to-hex-string h))
  (format t "~% J₀: ~X~%" (byte-vector-to-hex-string j0))
  (format t " last bit of j0: ~a~%" (ldb (byte 1 0) (aref j0 15)))
  (format t " lengt GHASH input: ~a~%" (length ghash-input))
  (format t " CT: ~X~%" ct)
  (format t "~%📐 Expected digest (derived): ~X~%"
        (byte-vector-to-hex-string (coerce (loop for i below 16 collect
              (logxor (aref expected-tag i) (aref tag-base i))) 'vector)))
  (format t "~%📐 GHASH digest: ~X~%" (byte-vector-to-hex-string s))
  (format t "~%🔄 Tag base (AES(K, J₀)): ~X~%" (byte-vector-to-hex-string tag-base))
  (format t "~%🎯 Computed tag: ~X~%" (byte-vector-to-hex-string computed-tag))
  (format t "~%📏 Expected tag: ~X~%" (byte-vector-to-hex-string expected-tag))
  
  ;; Compare tags
  (if (equalp computed-tag expected-tag)
      (format t "~%✅ TAG MATCHES!~%")
      (format t "~%❌ TAG MISMATCH.~%")))
