(defpackage :tls-aes192-gcm
  (:use :cl :shared-utils :tls-aes-utils :tls-aes-ghash :tls-aes192)
  (:export :aes192-gcm-encrypt :aes192-gcm-decrypt))

(in-package :tls-aes192-gcm)

(defun gctr-192 (key icb plaintext)
  (let ((blocks (chunk-all plaintext))
        (out '()))
    (loop for blk in blocks
          for ctr = (inc-counter icb) then (inc-counter ctr)
          for ek = (aes192-ecb-encrypt ctr key t nil)
          collect (map 'vector #'logxor ek blk) into out
          finally (return (apply #'concatenate '(vector (unsigned-byte 8)) out)))))

(defun aes192-gcm-encrypt (plaintext key iv &optional (aad #()) (taglen 128) (aad-len 0) (ctlen 0) verbose)
  "Encrypts plaintext using AES-GCM. Returns (ciphertext truncated-tag)."
  (let* ((expanded-key
          (cond ((= (length key) 24) (expand-key-192 key))
                (t (error "Invalid AES key length: ~D" (length key)))))
         (h (aes192-ecb-encrypt (make-array 16 :element-type '(unsigned-byte 8)
                                            :initial-element 0)
                                expanded-key t nil))
	 (iv-bitlen (* (length iv) 8))
	 (j0 (if (= iv-bitlen 96) (concatenate '(vector (unsigned-byte 8)) iv #(#x0 #x0 #x0 #x01))
		 (let ((len-block (concatenate '(vector (unsigned-byte 8))
					       (int->block-64be 0) ;; aad must be 0 here!
					       (int->block-64be iv-bitlen)))) ;; iv
		   (ghash h (append (pad-blocks iv) (list len-block))))))
         (init-counter (copy-seq j0)))

    (let* ((ciphertext (gctr-192 expanded-key init-counter plaintext))
	   (aad-len (length aad))
	   (ctlen (length ciphertext))
	   (len-block (concatenate '(vector (unsigned-byte 8))
				   (int->block-64be (* aad-len 8)) ;; bitlen of AAD here
				   (int->block-64be (* ctlen 8)))) ;; bitlen of CT here
	   (ghash-in (append (pad-blocks aad) (pad-blocks ciphertext) (list len-block)))
           ;;(ghash-in (build-ghash-blocks aad ciphertext aad-len ctlen))
           (s (ghash h ghash-in))
           (tag-base (aes192-ecb-encrypt j0 expanded-key t nil))
           (full-tag (make-array 16 :element-type '(unsigned-byte 8))))

      (when (and (< iv-bitlen 64) verbose)
	(warn "IV too short — may weaken GCM security"))
      
      (when (> iv-bitlen 16384)
	(warn "Unusually long IV — GHASH performance may degrade"))
      
      (dotimes (i (length full-tag))
        (setf (aref full-tag i) (logxor (aref tag-base i) (aref s i))))

      (when verbose
	(progn
	  (format t "~&~%Ciphertext       : ~X"
		  (if (endp (coerce ciphertext 'list))
		      'empty
		      (byte-vector-to-hex-string ciphertext)))
	  (format t "~%Tag base         : ~X" (byte-vector-to-hex-string tag-base))
	  (if (and (numberp verbose) (= verbose 2))
	      (mapc (lambda (blk) (format t "~%GHASH Block      : ~{~2,'0X~}" (coerce blk 'list))) ghash-in)
	      (mapc (lambda (blk) blk) ghash-in))
	                          (format t "~%GHASH result (s) : ~X" (byte-vector-to-hex-string s))
				  (format t "~%Full TAG         : ~X" (byte-vector-to-hex-string full-tag))))
      (values ciphertext (truncate-tag full-tag taglen)))))

(defun aes192-gcm-decrypt (ciphertext key iv tag &optional (aad #()) (taglen 128) (aad-len 0) (ctlen 0) verbose)
  "Decrypts AES-GCM ciphertext. Returns plaintext if tag verifies, else error."
  (let* ((expanded-key
          (cond ((= (length key) 24) (expand-key-192 key))
                (t (error "Invalid AES key length: ~D" (length key)))))
         (h (aes192-ecb-encrypt (make-array 16 :element-type '(unsigned-byte 8)
                                            :initial-element 0)
                                expanded-key t nil))
	 (iv-bitlen (* (length iv) 8))
	 (j0 (if (= iv-bitlen 96) (concatenate '(vector (unsigned-byte 8)) iv #(#x0 #x0 #x0 #x01))
		 (let ((len-block (concatenate '(vector (unsigned-byte 8))
					       (int->block-64be 0) ;; aad must be 0 here!
					       (int->block-64be iv-bitlen)))) ;; iv part
		   (ghash h (append (pad-blocks iv) (list len-block))))))
         (init-counter (copy-seq j0)))

    (let* ((plaintext (gctr-192 expanded-key init-counter ciphertext))
	   (aad-len (length aad))
	   (ctlen (length ciphertext))
	   (len-block (concatenate '(vector (unsigned-byte 8))
				   (int->block-64be (* aad-len 8)) ;; bitlen of AAD 160 here
				   (int->block-64be (* ctlen 8)))) ;; bitlen of CT 256 here
	   (ghash-in (append (pad-blocks aad) (pad-blocks ciphertext) (list len-block)))
           ;;(ghash-in (build-ghash-blocks aad ciphertext aad-len ctlen))
           (s (ghash h ghash-in))
           (tag-base (aes192-ecb-encrypt j0 expanded-key t nil))
           (full-tag (make-array 16 :element-type '(unsigned-byte 8))))

      (when (and (< iv-bitlen 64) verbose)
	(warn "IV too short — may weaken GCM security"))
      
      (when (> iv-bitlen 16384)
	(warn "Unusually long IV — GHASH performance may degrade"))
      
      (dotimes (i 16)
        (setf (aref full-tag i) (logxor (aref tag-base i) (aref s i))))
      
      (if (equalp tag (truncate-tag full-tag taglen))
          (values plaintext tag)
          (error "Invalid authentication tag")))))
