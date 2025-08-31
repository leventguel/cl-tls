(in-package :tls-aes128)

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
       (pt  (hex-string-to-byte-vector "cb531fac69f77f4e87299c02b9")) ;; plaintext
       (ct (hex-string-to-byte-vector "80c727d9e98cf4a57450a14ff1"))
       (expected-tag (hex-string-to-byte-vector "521b79df92238143d13d1db87b"))

       ;; Expanded key + hash subkey
       (expanded-key (expand-key-128 key))
       (h (aes128-ecb-encrypt
           (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)
           key t nil))

       ;; Lengths in bits
       (iv-bitlen (* (length iv) 8))
       (aad-bitlen (* (length aad) 8))
       (pt-bitlen (* (length pt) 8))
       (ct-bitlen (* (length ct) 8))

       ;; Construct J₀
       (j0 (if (= iv-bitlen 96)
               (concatenate '(vector (unsigned-byte 8)) iv #(#x00 #x00 #x00 #x01))
               (let* ((s (- (* 128 (ceiling (/ iv-bitlen 128))) iv-bitlen))
                      (iv-pad
		       (concatenate '(vector (unsigned-byte 8)) iv
                                    (make-array (/ s 8) :element-type '(unsigned-byte 8) :initial-element #x0)))
                      (len-block
		       (concatenate '(vector (unsigned-byte 8))
                                    (make-array 8 :element-type '(unsigned-byte 8) :initial-element #x0)
                                    (int->block-64be iv-bitlen)))
                      (j0-input (append (chunk-blocks iv-pad) (list len-block))))
                 (ghash h j0-input))))

       ;; Compute GCTR with J₀ + 1
       (computed-ct
	(progn
	  (format t "PT length: ~A~%" (length pt))
	  (format t "PT bytes: ~{~2,'0X~^ ~}~%" (coerce pt 'list))
	  (gctr key (inc-counter j0) pt)))

       ;; Compute u and v in bytes
       (u-bits (- (* 128 (ceiling (/ aad-bitlen 128))) aad-bitlen))
       (v-bits (- (* 128 (ceiling (/ ct-bitlen 128))) ct-bitlen))
       (u-bytes (/ u-bits 8))
       (v-bytes (/ v-bits 8))

       ;; Pad AAD and CT
       (aad-padded (concatenate '(vector (unsigned-byte 8)) aad
                                (make-array u-bytes :element-type '(unsigned-byte 8) :initial-element 0)))
       (ct-padded  (concatenate '(vector (unsigned-byte 8)) ct
                                (make-array v-bytes :element-type '(unsigned-byte 8) :initial-element 0)))

       ;; GHASH input = AAD || CT || [len(AAD) || len(CT)]
       (len-block (concatenate '(vector (unsigned-byte 8))
                               (int->block-64be aad-bitlen)
                               (int->block-64be pt-bitlen)))
       (ghash-input (append (chunk-blocks aad-padded)
                            (chunk-blocks ct-padded)
                            (list len-block)))

       ;; Run GHASH
       (s (ghash h ghash-input))

       ;; Tag = AES(K, J₀) XOR GHASH digest
       (tag-base (aes128-ecb-encrypt j0 key t nil))
       (computed-tag (coerce (loop for i below (min (length tag-base) (length s))
                                   collect (logxor (aref tag-base i) (aref s i)))
                             'vector))
       (truncated-tag (subseq computed-tag 0 (length expected-tag)))

       ;; Check
       (tag-match (equalp truncated-tag expected-tag))
       (ct-match (equalp computed-ct ct)))

  ;; Warnings on IV
  (when (< iv-bitlen 64)
    (warn "⚠️ IV too short — may weaken GCM security"))
  (when (> iv-bitlen 16384)
    (warn "⚠️ Unusually long IV — GHASH performance may degrade"))

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
  (format t "J₀: ~X~%Length of J₀: ~D bytes~%" (byte-vector-to-hex-string j0) (length j0))
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
  (if tag-match
      (format t "~%✅ TAG MATCHES!~%")
      (format t "~%❌ TAG MISMATCH.~%"))
  (if ct-match
      (format t "~%✅ CT MATCHES!~%")
      (format t "~%❌ CT MISMATCH.~%")))
