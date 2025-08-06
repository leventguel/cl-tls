(in-package :tls-aes128)

(defun aes-gcm-aek-encrypt (K IV P A &optional (taglen 128))
  "NIST Algorithm 4: GCM-AEK encryption. Returns (C, T)"
  (let* ((expanded-key
          (if (= (length K) 16)
              (expand-key-128 K)
              (error "AES-GCM requires 128-bit key.")))
         
         ;; Step 1: H = AES_K(0^128)
         (zero-block (make-array 16 :element-type '(unsigned-byte 8)
                                :initial-element 0))
         (H (aes128-ecb-encrypt zero-block expanded-key t nil))

         ;; Step 2: Build J₀ from IV
         (J0 (if (= (length IV) 12)
                 ;; J₀ = IV || 0^31 || 1
                 (concatenate '(vector (unsigned-byte 8)) IV #(0 0 0 1))
                 ;; J₀ = GHASH_H(IV || pad || len(IV))
                 (ghash H (build-ghash-blocks #() IV 0 (length IV))))
              )

         ;; Step 3: Encrypt P via AES-CTR with inc₃₂(J₀)
         (J1 (increment-counter! (copy-seq J0)))
         (C (aes128-ctr-encrypt P expanded-key J1))

         ;; Step 4–5: GHASH_H(A || pad || C || pad || len(A) || len(C))
         (ghash-in (build-ghash-blocks A C))
         (S (ghash H ghash-in))

         ;; Step 6: Tag = AES_K(J₀) ⊕ S
         (tag-base (aes128-ecb-encrypt J0 expanded-key t nil))
         (Tag (make-array 16 :element-type '(unsigned-byte 8)))
         )
    
    ;; Final XOR: Tag = AES_K(J₀) ⊕ GHASH digest
    (dotimes (i 16)
      (setf (aref Tag i) (logxor (aref tag-base i) (aref S i))))

    ;; Step 7: Return (C, truncated-Tag)
    (values (subseq Tag 0 (/ taglen 8)) C)))
