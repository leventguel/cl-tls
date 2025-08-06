(in-package :tls-aes128)

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

(defun pad-right (data bit-padding)
  "Pads a vector of unsigned bytes with `bit-padding` bits of zeros on the right."
  (let* ((byte-padding (ceiling bit-padding 8))
         (zero-bytes (make-array byte-padding :element-type '(unsigned-byte 8) :initial-element 0)))
    (concatenate '(vector (unsigned-byte 8)) data zero-bytes)))

(defun pad-blocks (vec)
  (let ((blocks (chunk-blocks vec)))
    (if (zerop (mod (length vec) 16))
        blocks
        (append (subseq blocks 0 (- (length blocks) 1))
                (list (pad16 (car (last blocks))))))))

(defun chunk-all (vec &optional (size 16))
  (loop for i from 0 below (length vec) by size
        collect (subseq vec i (min (+ i size) (length vec)))))

(defun gf128-mul (x y)
  (let ((res 0)
        (R #xE1000000000000000000000000000000)
        (mask #xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF))
    (dotimes (i 128)
      (when (logbitp (- 127 i) y)
        (setf res (logxor res x)))
      (setf res (logand res mask)) ;; ✨ constrain res to 128 bits
      (setf x (if (logbitp 0 x)
		  (logand (logxor (ash x -1) R) mask) ;; constrain the operation itself
                  (logand (ash x -1) mask))) ;; constring the operation itself
      (setf x (logand x mask)))
    res))

(defun ghash (h blocks)
  (let ((h-int (block->int h))
	(y 0))
    (dolist (block blocks)
      (setf y (gf128-mul h-int (logxor y (block->int block)))))
    (int->block y)))

(defun gctr (key icb plaintext)
  ;; GCTR assumes icb is already J₀ + 1
  (let ((blocks (chunk-all plaintext))
        (out '())
        (ctr (copy-seq icb)))  ;; icb = J₀ + 1
    (loop for blk in blocks
          for ek = (aes128-ecb-encrypt ctr key t nil)
          do (progn
               (format t "~%CTR block: ~X~%" (byte-vector-to-hex-string ctr))
               (format t "Encrypted CTR block: ~X~%" (byte-vector-to-hex-string ek))
               (format t "PT: ~X~%" (byte-vector-to-hex-string blk))
               (format t "CT candidate: ~X~%~%" (byte-vector-to-hex-string
                                               (map 'vector #'logxor (subseq ek 0 (length blk)) blk)))
               (setf ctr (inc-counter ctr)))
          collect (map 'vector #'logxor (subseq ek 0 (length blk)) blk) into out
          finally (return (apply #'concatenate '(vector (unsigned-byte 8)) out)))))

(let* (;; NIST AES-GCM Encrypt Test 0
       (key (hex-string-to-byte-vector "16c51c89e38f343068941ceed2b6f62f"))
       (iv  (hex-string-to-byte-vector "76"))
       (aad (hex-string-to-byte-vector ""))
       (pt (hex-string-to-byte-vector "cb531fac69f77f4e87299c02b9"))
       (ct (hex-string-to-byte-vector "80c727d9e98cf4a57450a14ff1"))

       (key-bitlen (* (length key) 8))
       (iv-bitlen (* (length iv) 8))
       (aad-bitlen (* (length aad) 8))
       (pt-bitlen (* (length pt) 8))
       (ct-bitlen (* (length ct) 8))
       ;; Expanded key and subkey H
       (expanded-key (expand-key-128 key))
       (h (aes128-ecb-encrypt
           (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)
           key t nil))

       ;; Construct J₀
       (j0 (if (= iv-bitlen 96) (concatenate '(vector (unsigned-byte 8)) iv #(#x0 #x0 #x0 #x01))
               (let* ((s (- (* 128 (ceiling (/ iv-bitlen 128))) iv-bitlen))
		      (len-block
		       (concatenate '(vector (unsigned-byte 8))
				    (make-array (+ s 64) :element-type '(unsigned-byte 8) :initial-element #x0)
				    (int->block-64be iv-bitlen))))
		 (ghash h (append (pad-blocks iv) (list len-block))))))

       ;; Encrypt plaintext using AES-CTR (J₀ + 1)
       ;; Note: PT is only one block here
       (computed-ct (gctr key (inc-counter j0) pt))

       ;; GHASH input blocks: AAD + length
       ;; 0 AAD bits, 128 CT bits
       (len-block (concatenate '(vector (unsigned-byte 8))
                              (int->block-64be aad-bitlen) ;; bitlen of AAD here
                              (int->block-64be ct-bitlen))) ;; bitlen of CT
       (ghash-input (append (pad-blocks aad) (pad-blocks ct) (list len-block)))

       ;; Compute GHASH digest
       (s (ghash h ghash-input))

       ;; Compute tag base
       (tag-base (aes128-ecb-encrypt j0 key t nil))

       ;; Compute final tag
       (computed-tag (coerce (loop for i below (min (length tag-base) (length s))
				   collect (logxor (aref tag-base i) (aref s i))) 'vector))

       ;; Expected tag (from NIST test vector)
       (expected-tag (hex-string-to-byte-vector "521b79df92238143d13d1db87b"))
       (truncated-tag (subseq computed-tag 0 (length expected-tag)))
       (tag-match (equalp truncated-tag expected-tag))
       (ct-match (equalp computed-ct ct)))

  (when (< iv-bitlen 64)
    (warn "IV too short — may weaken GCM security"))

  (when (> iv-bitlen 16384)
    (warn "Unusually long IV — GHASH performance may degrade"))

  ;; Output comparison
  (format t "my-gash: ~{~2,'0X ~}~%"
	  (coerce
	   (ghash h
		  (list #(#x76 #x00 #x00 #x00 #x00 #x00 #x00 #x00 #x00 #x00 #x00 #x00 #x00 #x00 #x00 #x00)
			#(#x00 #x00 #x00 #x00 #x00 #x00 #x00 #x00 #x00 #x00 #x00 #x00 #x00 #x00 #x00 #x08))) 'list))

  (format t "~%🧪 GHASH blocks:~%")
  (loop for blk in ghash-input
        for idx from 0
        do (format t "  Block ~D: ~X~%" idx (byte-vector-to-hex-string blk)))
  
  (gctr key j0 pt)
  (let ((blocks (chunk-blocks ct)))
    (format t "CT chunk count: ~D~%" (length blocks))
    (loop for b in blocks and i from 0
          do (format t "Block ~D length: ~D~%" i (length b))))

  ;; Output
  (format t "~%🔐 H subkey: ~X~%" (byte-vector-to-hex-string h))
  (format t "~%J₀: ~X~%" (byte-vector-to-hex-string j0))
  (format t "Length of J₀: ~D~%" (length j0))
  (format t " last bit of j0: ~a~%" (ldb (byte 1 0) (aref j0 15)))
  (format t "~%CTR base: J₀ + 1: ~X~%" (byte-vector-to-hex-string (inc-counter j0)))
  (format t " lengt GHASH input: ~a~%" (length ghash-input))

  (format t "~%📐 GHASH digest: ~X~%" (byte-vector-to-hex-string s))
  (format t "📐 Expected digest (derived): ~X~%"
	  (byte-vector-to-hex-string
	   (coerce (loop for i below (length expected-tag) collect
			 (logxor (aref expected-tag i) (aref tag-base i))) 'vector)))
  
  (format t "~%🧮 Computed CT: ~X~%" (byte-vector-to-hex-string computed-ct))
  (format t "📏 Expected CT: ~X~%" (byte-vector-to-hex-string ct))
  (format t "~%🎯 Computed tag: ~X~%" (byte-vector-to-hex-string truncated-tag))
  (format t "📐 Expected tag: ~X~%" (byte-vector-to-hex-string expected-tag))
  
  ;; Compare tags
  (if tag-match
      (format t "~%✅ TAG MATCHES!~%")
      (format t "~%❌ TAG MISMATCH.~%"))
  (if ct-match
      (format t "~%✅ CT MATCHES!~%")
      (format t "~%❌ CT MISMATCH.~%")))
