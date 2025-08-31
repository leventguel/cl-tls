(defpackage :des-triple-mac
  (:use :cl :shared-utils :des-utils :des-padding :des-base64 :des-constants :des-core :des-context :des-api)
  (:export :tdes-cmac))

(in-package :des-triple-mac)

(defun pad-block (block)
  (let ((pad-len (- 8 (length block))))
    (concatenate '(vector (unsigned-byte 8))
                 block
                 (list #x80)
                 (make-array (- pad-len 1) :element-type '(unsigned-byte 8) :initial-element 0))))

(defun cmac-subkey-shift (block)
  (let* ((n (length block))
         (shifted (make-array n :element-type '(unsigned-byte 8)))
         (carry 0))
    ;; Shift left by 1 bit across all bytes
    (dotimes (i n)
      (let* ((index (- n i 1))
             (byte (aref block index))
             (new-byte (logior (ash byte 1) carry)))
        (setf carry (if (logtest byte #x80) 1 0))
        (setf (aref shifted index) (logand new-byte #xFF))))
    ;; If MSB of original block is set, XOR last byte with Rb
    (when (logtest (aref block 0) #x80)
      (setf (aref shifted (1- n))
            (logxor (aref shifted (1- n)) #x1B)))
    shifted))

(defun tdes-ecb-encrypt-block (block tdes-keys)
  "Encrypts a block using Triple DES (EDE with K1 = K3)."
  (let ((K1 (aref tdes-keys 0))
        (K2 (aref tdes-keys 1))
        (K3 (aref tdes-keys 2)))
    (des-ecb-encrypt-block
     (des-ecb-decrypt-block
      (des-ecb-encrypt-block (ensure-bit-vector block) K1)
      K2)
     K3)))

(defun prepare-tdes-keys (key &optional verbose-p)
  "Prepares TDES round keys from a 16- or 24-byte key."
  (let* ((key-bytes (if (bit-vector-p key) (bit-vector-to-byte-vector key) key))
         (key-length (length key-bytes)))
    (cond
      ((= key-length 16)
       ;; 2-key TDES: K1, K2, K1
       (let* ((K1 (subseq key-bytes 0 8))
              (K2 (subseq key-bytes 8 16))
              (result (vector (generate-round-keys K1)
			      (generate-round-keys K2)
			      (generate-round-keys K1))))
	 (when verbose-p
	   (progn
	     (format t "~%2-Key case")
	     (format t "~%Length: ~A" key-length)
	     (format t "~%K1: ~A" K1)
	     (format t "~%K2: ~A" K2)))
	 result))
      ((= key-length 24)
       ;; 3-key TDES: K1, K2, K3
       (let* ((K1 (subseq key-bytes 0 8))
              (K2 (subseq key-bytes 8 16))
              (K3 (subseq key-bytes 16 24))
              (result (vector (generate-round-keys K1)
			      (generate-round-keys K2)
			      (generate-round-keys K3))))
	 (when verbose-p
	   (progn
	     (format t "~%3-Key case")
	     (format t "~%Length: ~A" key-length)
	     (format t "~%K1: ~A" K1)
	     (format t "~%K2: ~A" K2)))
	 result))
      (t
       (error "TDES key must be 16 or 24 bytes long")))))

(defun generate-subkeys-tdes (key)
  "Generate CMAC subkeys K1 and K2 from a Triple DES key."
  (let* ((tdes-keys (prepare-tdes-keys key))
         (zero-block (make-array 8 :element-type '(unsigned-byte 8) :initial-element 0))
	 (L0 (tdes-ecb-encrypt-block zero-block tdes-keys))
         (L (if (bit-vector-p L0) (bit-vector-to-byte-vector L0) L0))
         (K1 (cmac-subkey-shift L))
         (K2 (cmac-subkey-shift K1)))
    (values K1 K2)))

(defun tdes-cmac (msg key1 key2 key3 tlen &optional verbose-p show-msg-len)
  "Computes CMAC using TDES and returns tlen-byte MAC."
  (let* ((key (if (equalp key1 key3)
                  (concatenate '(vector (unsigned-byte 8)) key1 key2)
                  (concatenate '(vector (unsigned-byte 8)) key1 key2 key3))))
    (multiple-value-bind (K1 K2) (generate-subkeys-tdes key)
      (let* ((blocks (split-into-blocks msg 8))
             (tdes-keys (prepare-tdes-keys key))
             (prev (make-array 8 :element-type '(unsigned-byte 8) :initial-element 0)))
	
	(assert (and (vectorp tdes-keys)
		     (= (length tdes-keys) 3)
		     (every #'vectorp tdes-keys)))

	(when verbose-p
	  (progn
	    (when (and (numberp verbose-p) (or (= verbose-p 2) (= verbose-p 3)))
	      (format t "~%Block: ~{~A ~} ~%(real Blocklen: ~A)~%"
		      (subseq
		       (coerce (concatenate 'vector (mapcar #'byte-vector-to-hex-string blocks)) 'list)
		       0 (min (/ show-msg-len 8) (length blocks)))
		      (length blocks)))
	    (format t "~%Key  : ~A~%" (byte-vector-to-hex-string key))))

	(when (and (numberp verbose-p) (= verbose-p 3))
	  (format t "TDESKeys: ~A~%" tdes-keys))
	
	(cond
	  ;; Empty message: use padded zero-block and K2
          ((null blocks)
           (setf prev
		 (tdes-ecb-encrypt-block
                  (xor-blocks (pad-block #()) K2)
                  tdes-keys)))
	  ;; Non-empty message
          (t
           (let* ((n (length blocks))
		  (last-block (if (= (length msg) (* 8 (length blocks)))
				  (xor-blocks (nth (- n 1) blocks) K1)
				  (xor-blocks (pad-block (nth (- n 1) blocks)) K2))))
	     (loop for i from 0 below (- n 1)
		   do (setf prev
			    (bit-vector-to-byte-vector (tdes-ecb-encrypt-block
							(xor-blocks (nth i blocks) prev)
							tdes-keys))))
             (setf prev
                   (tdes-ecb-encrypt-block
                    (xor-blocks prev last-block)
                    tdes-keys)))))

	(when verbose-p
	  (format t "Prev : ~A~%" (byte-vector-to-hex-string (bit-vector-to-byte-vector prev))))

	(subseq (if (bit-vector-p prev) (bit-vector-to-byte-vector prev) prev) 0 tlen)))))

