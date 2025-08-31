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

(defun pad16 (block)
  (let* ((blen (length block))
         (padded (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)))
    (if (> blen 16)
        (error "Block too long to pad: ~D bytes" blen)
        (replace padded block))
    padded))

(defun pad-blocks (vec)
  (let ((blocks (chunk-blocks vec)))
    (if (zerop (mod (length vec) 16))
        blocks
        (append (subseq blocks 0 (- (length blocks) 1))
                (list (pad16 (car (last blocks))))))))

(defun chunk-all (vec &optional (size 16))
  (loop for i from 0 below (length vec) by size
        collect (subseq vec i (min (+ i size) (length vec)))))

(defmacro safe-xor-vectors (a b)
  `(loop for i below (min (length ,a) (length ,b))
         collect (logxor (aref ,a i) (aref ,b i))))

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
  (let ((blocks (chunk-all plaintext))
        (out '()))
    (loop for blk in blocks
          for ctr = (inc-counter icb) then (inc-counter ctr)
          for ek = (aes128-ecb-encrypt ctr key t nil)
          collect (map 'vector #'logxor ek blk) into out
          finally (return (apply #'concatenate '(vector (unsigned-byte 8)) out)))))

(let* (;; NIST AES-GCM Encrypt Test 0
       (key (hex-string-to-byte-vector "5a28a3005ea0b75fe7090ef1450457c3"))
       (iv  (hex-string-to-byte-vector "df6f0ac6d729e65d779984f0f548459a458c46029d6e05c66dafc39b16a22c8b5948172ec9697a452ec123b6df34ef5deb39739857829f235357940b4ca81b41c0c0c84a95fb0abec254da694e70cbc312ed17926a9684bfdbc6a2dfa43d713d379485e086ff96214c82a81d2de4ec699ad0efe3a344e2cff261c492f5141560"))
       (aad (hex-string-to-byte-vector "ff6e0fdb550c5dcf006b773d9e6987971657b2a3"))
       (pt (hex-string-to-byte-vector "17f74678b64b0ad6714e74f001b8527b5148a2b1e27b7e2a920760688f15dbc1"))
       (ct (hex-string-to-byte-vector "e7200c8c81f49a38f044f7945e0c253b6e7c9b52cc473119f7c6badd59d3bb0e"))

       ;; Expanded key and subkey H
       (expanded-key (expand-key-128 key))
       (h (aes128-ecb-encrypt
           (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)
           expanded-key t nil))
       (iv-bitlen (* (length iv) 8))
       ;; Construct J₀
       (j0 (if (= iv-bitlen 96) (concatenate '(vector (unsigned-byte 8)) iv #(#x0 #x0 #x0 #x01))
	       (let ((len-block (concatenate '(vector (unsigned-byte 8))
                               (int->block-64be 0) ;; aad must be 0 here!
                               (int->block-64be iv-bitlen)))) ;; iv should be 1024 in this case
		 (ghash h (append (pad-blocks iv) (list len-block))))))

       ;; Encrypt plaintext using AES-CTR (J₀ + 1)
       ;; Note: PT is only one block here
       (ct (gctr expanded-key j0 pt))

       ;; GHASH input blocks: AAD + length
       ;; 0 AAD bits, 128 CT bits
       (len-block (concatenate '(vector (unsigned-byte 8))
                              (int->block-64be (* (length aad) 8)) ;; bitlen of AAD 160 here
                              (int->block-64be (* (length ct) 8)))) ;; bitlen of CT 256 here
       (ghash-input (append (pad-blocks aad) (pad-blocks ct) (list len-block)))

       ;; Compute GHASH digest
       (s (ghash h ghash-input))

       ;; Compute tag base
       (tag-base (aes128-ecb-encrypt j0 expanded-key t nil))

       ;; Compute final tag
       (computed-tag (coerce (loop for i below (min (length tag-base) (length s))
				   collect (logxor (aref tag-base i) (aref s i))) 'vector))

       ;; Expected tag (from NIST test vector)
       (expected-tag (hex-string-to-byte-vector "d669293d72dc98285828696cb5df2d"))
       (truncated-tag (subseq computed-tag 0 (length expected-tag)))
       (tag-match (equalp truncated-tag expected-tag)))

  (when (< iv-bitlen 64)
    (warn "IV too short — may weaken GCM security"))

  (when (> iv-bitlen 16384)
    (warn "Unusually long IV — GHASH performance may degrade"))

  ;; Output comparison
  (format t "~%🧪 GHASH blocks:~%")
  (loop for blk in ghash-input
        for idx from 0
        do (format t "  Block ~D: ~X~%" idx (byte-vector-to-hex-string blk)))

  (format t "~%🔐 H subkey: ~X~%" (byte-vector-to-hex-string h))
  (format t "~% J₀: ~X~%" (byte-vector-to-hex-string j0))
  (format t "Length of J₀: ~D~%" (length j0))
  (format t " last bit of j0: ~a~%" (ldb (byte 1 0) (aref j0 15)))
  (format t " lengt GHASH input: ~a~%" (length ghash-input))
  (format t " CT: ~X~%" ct)
  (format t "Length of CT: ~D~%" (length ct))
  (let ((blocks (chunk-blocks ct)))
    (format t "CT chunk count: ~D~%" (length blocks))
    (loop for b in blocks and i from 0
          do (format t "Block ~D length: ~D~%" i (length b))))
  (format t "~%📐 Expected digest (derived): ~X~%"
	  (byte-vector-to-hex-string
	   (coerce (loop for i below (length expected-tag) collect
			 (logxor (aref expected-tag i) (aref tag-base i))) 'vector)))
  (format t "~%📐 GHASH digest: ~X~%" (byte-vector-to-hex-string s))
  (format t "~%🔄 Tag base (AES(K, J₀)): ~X~%" (byte-vector-to-hex-string tag-base))
  (format t "~%🎯 Computed tag: ~X~%" (byte-vector-to-hex-string computed-tag))
  (format t "~%🎯 Truncate computed tag to taglength: ~X~%" (byte-vector-to-hex-string truncated-tag))
  (format t "~%📏 Expected tag: ~X~%" (byte-vector-to-hex-string expected-tag))
  
  ;; Compare tags
  (if tag-match
      (format t "~%✅ TAG MATCHES!~%")
      (format t "~%❌ TAG MISMATCH.~%")))
