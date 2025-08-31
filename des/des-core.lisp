(defpackage :des-core
  (:use :cl :shared-utils :des-utils :des-padding :des-constants)
  (:export :+des-initial-permutation+ :+des-final-permutation+ :+des-expansion-table+ :+des-permutation-p+
	   :+des-pc1+ :+des-pc2+ :+des-left-shifts+ :+des-sboxes+
	   :permute-bits :generate-cd-pairs :apply-pc1 :apply-pc2 :generate-round-keys
	   :sbox-index :substitute-sboxes :feistel
	   :des-ecb-encrypt-block :des-ecb-decrypt-block
	   :des-ecb-encrypt-plain :des-ecb-decrypt-plain :des-ecb-encrypt :des-ecb-decrypt
	   :des-cbc-encrypt-plain :des-cbc-decrypt-plain :des-cbc-encrypt :des-cbc-decrypt
	   :des-cfb-encrypt-plain :des-cfb-decrypt-plain :des-cfb8-encrypt-plain :des-cfb8-decrypt-plain
	   :des-cfb1-encrypt-plain :des-cfb1-decrypt-plain
	   :des-ofb-encrypt-plain :des-ofb-decrypt-plain
	   :des-ctr-encrypt-plain :des-ctr-decrypt-plain))

(in-package :des-core)

(defun permute-bits (input table)
  ;; Permutation tables in DES are defined over bits, not bytes.
  ;; Changing to full octets here will break the bit-level semantics.
  ;; You might still get output, but it will be semantically corrupted — 
  ;; the permutation will no longer reflect the intended bit positions.
  (let ((output (make-array (length table) :element-type '(unsigned-byte 1)))) ;; 1 bit elements
    (loop for i from 0 below (length table)
          for table-value = (1- (aref table i))
          do (setf (aref output i) (aref input table-value)))
    output))

(defun permute-bits-byte (input table)
  (bit-vector-to-byte-vector
   (permute-bits (byte-vector-to-bit-vector input) table)))

(defun generate-cd-pairs (C0 D0)
  "Generate 16 combined CD vectors after left shifts."
  (let ((C C0)
        (D D0)
        cd-list)
    (loop for shift across +des-left-shifts+
          do (setf C (left-shift C shift)
                   D (left-shift D shift))
          (push (concatenate 'vector C D) cd-list))
    (nreverse cd-list)))

;; IP is initial permutations
;; FP is final permutations
;; PC is permuted choice (pc1 is with parity cut)
(defun apply-pc1 (key)
  "Apply PC-1 to a 64-bit key to get a 56-bit key."
  (permute-bits key +des-pc1+))

(defun apply-pc1 (key)
  "Apply PC-1 to a 64-bit key to get a 56-bit key."
  (permute-bits (ensure-bit-vector key) +des-pc1+))

(defun apply-pc2 (cd)
  "Apply PC-2 permutation to 56-bit CD vector to get 48-bit round key."
  (let ((key (make-array 48 :element-type '(unsigned-byte 8))))
    (dotimes (i 48)
      (setf (aref key i) (aref cd (1- (aref +des-pc2+ i)))))
    key))

(defun apply-pc2 (bit-vector)
  (map 'vector (lambda (i)
                 (aref bit-vector (1- i))) ; PC-2 is 1-based
       +des-pc2+))

(defun fix-parity (key64)
  "Ensure each byte in key64 has odd parity."
  (map 'vector
       (lambda (byte)
         (let ((ones (count 1 (int-to-bit-vector byte 8))))
           (if (oddp ones) byte (logxor byte 1)))) ; flip LSB if parity is even
       key64))

(defun generate-round-keys (key64 &optional (fix-parity-p nil) (verbose nil))
  "Generate 16 DES round keys from a 64-bit key."
  (let* ((key-bytes (if fix-parity-p (fix-parity key64) key64))
         (key64-bits (ensure-bit-vector key-bytes))
         (key56 (apply-pc1 key64-bits))
         (C0 (subseq key56 0 28))
         (D0 (subseq key56 28 56))
         (cd-pairs (generate-cd-pairs C0 D0)))
    (when verbose
      (progn
	(format t "C0: ~A~%" C0)
	(format t "D0: ~A~%" D0)
	(format t "length CD pairs: ~A~%" (length cd-pairs))))
    (map 'vector #'apply-pc2 cd-pairs)))

(defun sbox-index (bits)
  "Compute the index into an S-box from a 6-bit vector."
  (let ((row (+ (* (aref bits 0) 2) (aref bits 5)))
        (col (+ (* (aref bits 1) 8)
                (* (aref bits 2) 4)
                (* (aref bits 3) 2)
                (aref bits 4))))
    (+ (* row 16) col))) ;; index = row * 16 + col

(defun substitute-sboxes (input48)
  "Substitute using the 8 DES S-boxes."
  (let ((chunks (split-into-6bit-chunks input48)))
    (apply #'concatenate 'vector
           (loop for i from 0 below 8
		 for chunk = (aref chunks i)
		 for index = (sbox-index chunk)
		 for sbox = (aref +des-sboxes+ i)
		 for val = (aref sbox index)
		 collect (int-to-bit-vector val 4)))))

(defun feistel (R K)
  "Feistel function: expands R, XORs with K, substitutes via S-boxes, permutes."
  (let* ((expanded (permute-bits R +des-expansion-table+))
         (xored (map 'vector #'logxor expanded K))
         (substituted (substitute-sboxes xored))
         (permuted (permute-bits substituted +des-permutation-p+)))
    permuted))

(defun des-ecb-encrypt-block (block round-keys &optional (verbose nil))
  "Encrypt a 64-bit block using DES."
  (let* ((block (ensure-bit-vector block))
         (IP-block (permute-bits block +des-initial-permutation+))
         (L (subseq IP-block 0 32))
         (R (subseq IP-block 32 64)))
    ;; 16 rounds
    (dotimes (i 16)
      (let* ((K (aref round-keys i))
	     (f (feistel R K)))
	(when verbose
	  (progn
	    (format t "~%Encrypt Round ~D~%" i)
            (format t "Encrypt L: ~A~%" L)
            (format t "Encrypt R: ~A~%" R)
            (format t "Encrypt K: ~A~%" K)
            (format t "Encrypt Feistel output (round ~D) f(R,K): ~A~%" i (feistel R K))
	    (format t "Encrypt length block:      ~a~%" (length block)) ;; should be 8
	    (format t "Encrypt length total round-keys: ~a~%" (length round-keys)) ;; should be 16
	    ;; should all be 48
	    (format t "Encrypt each round-key lengths: ~a~%" (mapcar #'length (coerce round-keys 'list)))))
        (psetf L R
	       R (map 'vector #'logxor L f))))
    (let ((preoutput (concatenate 'bit-vector R L)))
      (permute-bits preoutput +des-final-permutation+))))

(defun des-ecb-decrypt-block (block round-keys &optional (verbose nil))
  "Decrypt a 64-bit block using DES with verbose round output."
  (let* ((block (ensure-bit-vector block))
         (IP-block (permute-bits block +des-initial-permutation+))
         (R (subseq IP-block 0 32))
         (L (subseq IP-block 32 64)))
    ;; 16 rounds in reverse
    (loop for i from 15 downto 0 do
	  (let* ((K (aref round-keys i))
		 (f (feistel L K)))
	    (when verbose
	      (progn
		(format t "~%Decrypt Round ~D~%" i)
		(format t "Decrypt L: ~A~%" L)
		(format t "Decrypt R: ~A~%" R)
		(format t "Decrypt K: ~A~%" K)
		(format t "Decrypt Feistel output (round ~D) f(R,K): ~A~%" i (feistel L K))
		(format t "Decrypt length block:      ~a~%" (length block)) ;; should be 8
		(format t "Decrypt length total round-keys: ~a~%" (length round-keys)) ;; should be 16
		;; should all be 48
		(format t "Decrypt each round-key lengths: ~a~%" (mapcar #'length (coerce round-keys 'list)))))
	    (psetf R L
		   L (map 'vector #'logxor R f))))
    (let ((preoutput (concatenate 'bit-vector L R))) ;; final swap
      (permute-bits preoutput +des-final-permutation+))))

;; ECB mode
;; plain means no padding
(defun des-ecb-encrypt-plain (blocks key)
  (let* ((key (ensure-bit-vector key))
	(round-keys (generate-round-keys key t)))
    (mapcar (lambda (block)
	      (des-ecb-encrypt-block block round-keys))
	    blocks)))

;; ECB mode
;; plain means no padding
(defun des-ecb-decrypt-plain (blocks key)
  (let* ((key (ensure-bit-vector key))
	(round-keys (generate-round-keys key t)))
    (mapcar (lambda (block)
	      (des-ecb-decrypt-block block round-keys))
	    blocks)))

;;ECB mode with padding
(defun des-ecb-encrypt (plaintext key)
  (let* ((key (ensure-bit-vector key))
	 (padded (pad-byte-vector plaintext 8))
         (blocks (split-into-blocks padded 8))
         (cipher-blocks (des-ecb-encrypt-plain blocks key)))
    (mapcar #'bit-vector-to-byte-vector cipher-blocks)))

;; ECB mode with padding
(defun des-ecb-decrypt (ciphertext key)
  (let* ((key (ensure-bit-vector key))
	 (decrypted-blocks (des-ecb-decrypt-plain ciphertext key))
         (bytes (apply #'concatenate 'vector
                       (mapcar #'bit-vector-to-byte-vector decrypted-blocks))))
    (unpad-byte-vector bytes)))

;; CBC mode
;; plain means no padding involved here
(defun des-cbc-encrypt-plain (blocks key iv &optional (verbose nil))
  (let ((previous-block (ensure-bit-vector iv))
        (round-keys (generate-round-keys key t))
	result)
    (dolist (block blocks)
      (let* ((block (ensure-bit-vector block))
	     (xored (map 'bit-vector #'logxor block previous-block))) ;; use bit-vector here or risk corruption!
	(when verbose
	  (progn
	    (format t "Previous plaintext block: ~A~%" previous-block)
	    (format t "Current plaintext block: ~A~%" block)
	    (format t "XOR with previous: ~A~%" xored)))
	(let ((ciphertext (des-ecb-encrypt-block xored round-keys)))
	  (when verbose
	    (format t "Encrypted xored (plaintext) block: ~A~%" ciphertext))
          (push ciphertext result)
          (setf previous-block ciphertext))))
    (nreverse result)))

;; CBC mode
;; plain means no padding involved here
(defun des-cbc-decrypt-plain (blocks key iv &optional (verbose nil))
  (let ((previous-block (ensure-bit-vector iv))
	(round-keys (generate-round-keys key t))
	result)
    (dolist (block blocks)
      (let* ((block (ensure-bit-vector block))
	     (plaintext (des-ecb-decrypt-block block round-keys)))
	(when verbose
	  (progn
	    (format t "Previous ciphertext block: ~A~%" previous-block)
	    (format t "Current ciphertext block: ~A~%" block)))
	;; use of bit-vector here is optional as long as the encryption part uses it
	;; to be on the safe side leave it as bit-vector.
	(let ((xored (map 'bit-vector #'logxor plaintext previous-block)))
	  (when verbose
	    (progn
	      (format t "XOR with previous: ~A~%" xored)
	      (format t "Decrypted xored (ciphertext) block: ~A~%" plaintext)))
          (push xored result)
          (setf previous-block block))))
    (nreverse result)))

;; CBC mode
(defun des-cbc-encrypt (plaintext key iv)
  (let* ((padded (pad-byte-vector plaintext 8))
         (blocks (split-into-blocks padded 8))
         (cipher-blocks (des-cbc-encrypt-plain blocks key iv)))
    (mapcar #'bit-vector-to-byte-vector cipher-blocks)))

;; CBC mode
(defun des-cbc-decrypt (ciphertext key iv)
  (let* ((decrypted-blocks (des-cbc-decrypt-plain ciphertext key iv))
         (bytes (apply #'concatenate 'vector
                       (mapcar #'bit-vector-to-byte-vector decrypted-blocks))))
    (unpad-byte-vector bytes)))

;; CFB mode
;; CFB modes don't require padding
;; 8 Byte (64bit)
(defun des-cfb-encrypt-plain (blocks key iv)
  (let* ((key (ensure-bit-vector key))
	(input-block (ensure-bit-vector iv))
        (round-keys (generate-round-keys key t))
        result)
    (dolist (block blocks)
      (let* ((output (des-ecb-encrypt-block input-block round-keys))
	     (segment (subseq output 0 (length block))) ; ← match block length
	     (ciphertext (map 'vector #'logxor block segment)))
        (push ciphertext result)
        (setf input-block ciphertext)))
    (nreverse result)))

;; CFB mode
;; CFB modes don't require padding
;; 8 Byte (64bit)
(defun des-cfb-decrypt-plain (ciphertext key iv)
  (let* ((key (ensure-bit-vector key))
	 (plaintext (make-array 0 :element-type '(unsigned-byte 8)
				:adjustable t :fill-pointer t))
	 (round-keys (generate-round-keys key t))
         (prev-cipher (ensure-bit-vector iv)))
    (loop for block in ciphertext do
	  (let* ((encrypted (des-ecb-encrypt-block prev-cipher round-keys))
		 (segment (subseq encrypted 0 (length block)))
		 (plain-block (map 'vector #'logxor block segment)))
	    (loop for byte across plain-block do
		  (vector-push-extend byte plaintext))
    ;; CFB chaining: update prev-cipher with the ciphertext block
	    (setf prev-cipher block)))
    plaintext))

;; CFB mode
;; CFB modes don't require padding
;; 1 Byte (8bit)
(defun des-cfb8-encrypt-plain (plaintext key iv)
  (let* ((key (ensure-bit-vector key))
         (feedback (ensure-bit-vector iv))
         (round-keys (generate-round-keys key t))
         (ciphertext (make-array 0 :element-type '(unsigned-byte 8)
                                 :adjustable t :fill-pointer t)))
    (loop for byte across plaintext do
          (let* ((encrypted (des-ecb-encrypt-block feedback round-keys))
                 (keystream-byte (aref encrypted 0))
                 (cipher-byte (logxor byte keystream-byte)))
            (vector-push-extend cipher-byte ciphertext)
            ;; Shift feedback left by 1 byte and append new cipher byte
            (setf feedback (concatenate 'vector (subseq feedback 1) (vector cipher-byte)))))
    ciphertext))

;; CFB mode
;; CFB modes don't require padding
;; 1 Byte (8bit)
(defun des-cfb8-decrypt-plain (ciphertext key iv)
  (let* ((key (ensure-bit-vector key))
         (feedback (ensure-bit-vector iv))
         (round-keys (generate-round-keys key t))
         (plaintext (make-array 0 :element-type '(unsigned-byte 8)
                                :adjustable t :fill-pointer t)))
    (loop for byte across ciphertext do
          (let* ((encrypted (des-ecb-encrypt-block feedback round-keys))
                 (keystream-byte (aref encrypted 0))
                 (plain-byte (logxor byte keystream-byte)))
            (vector-push-extend plain-byte plaintext)
            ;; Shift feedback left by 1 byte and append ciphertext byte
            (setf feedback (concatenate 'vector (subseq feedback 1) (vector byte)))))
    plaintext))

;; CFB mode
;; CFB modes don't require padding
;; 1 Bit
(defun des-cfb1-encrypt-plain (bitstream key iv)
  (let* ((key (ensure-bit-vector key))
         (feedback (ensure-bit-vector iv))
         (round-keys (generate-round-keys key t))
         (cipher-bits '()))
    (loop for bit in bitstream do
          (let* ((encrypted (des-ecb-encrypt-block feedback round-keys))
                 (keystream-bit (ldb (byte 1 0) (aref encrypted 0)))
                 (cipher-bit (logxor bit keystream-bit)))
            (push cipher-bit cipher-bits)
            (setf feedback (shift-buffer-bit feedback cipher-bit))))
    (nreverse cipher-bits)))

;; CFB mode
;; CFB modes don't require padding
;; 1 Bit
(defun des-cfb1-decrypt-plain (cipher-bits key iv)
  (let* ((key (ensure-bit-vector key))
         (feedback (ensure-bit-vector iv))
         (round-keys (generate-round-keys key t))
         (plaintext-bits '()))
    (loop for bit in cipher-bits do
          (let* ((encrypted (des-ecb-encrypt-block feedback round-keys))
                 (keystream-bit (ldb (byte 1 0) (aref encrypted 0)))
                 (plain-bit (logxor bit keystream-bit)))
            (push plain-bit plaintext-bits)
            (setf feedback (shift-buffer-bit feedback bit))))
    (nreverse plaintext-bits)))

;; OFB mode
;; Similar to CFB modes OFB modes don't require padding
(defun des-ofb-encrypt-plain (plaintext key iv)
  (let* ((key (ensure-bit-vector key))
         (feedback (ensure-bit-vector iv))
         (round-keys (generate-round-keys key t))
         (ciphertext (make-array 0 :element-type '(unsigned-byte 8)
                                 :adjustable t :fill-pointer t)))
    (loop for byte across plaintext do
          (let* ((encrypted (des-ecb-encrypt-block feedback round-keys))
                 (keystream-byte (aref encrypted 0))
                 (cipher-byte (logxor byte keystream-byte)))
            (vector-push-extend cipher-byte ciphertext)
            (setf feedback encrypted))) ; feedback is updated with encrypted output
    ciphertext))

;; OFB mode
;; Similar to CFB modes OFB modes don't require padding
(defun des-ofb-decrypt-plain (ciphertext key iv)
  ;; identical to encryption — OFB is symmetric
  (des-ofb-encrypt-plain ciphertext key iv))

;; CTR mode
;; Similar to CFB modes CTR modes don't require padding
;; Note: Unlike OFB, CTR modifies the IV (counter) during encryption,
;; so it must be a mutable byte vector (e.g., #(1 2 3 4 5 6 7 8)), not a bit-vector.
;; so IV is passed as is here (without converting to bit-vector) but copied
;; in order to prevent accidental hampering on the original value (since we are mutating it via increment-counter) 
(defun des-ctr-encrypt-plain (plaintext key iv)
  (let* ((key (ensure-bit-vector key))
         (counter (copy-seq iv))
         (round-keys (generate-round-keys key t))
         (ciphertext (make-array 0 :element-type '(unsigned-byte 8)
                                 :adjustable t :fill-pointer t)))
    (loop for byte across plaintext do
          (let* ((encrypted (des-ecb-encrypt-block counter round-keys))
                 (keystream-byte (aref encrypted 0))
                 (cipher-byte (logxor byte keystream-byte)))
            (vector-push-extend cipher-byte ciphertext)
            (setf counter (increment-counter counter))))
    ciphertext))

;; CTR mode
;; Similar to CFB modes CTR modes don't require padding
(defun des-ctr-decrypt-plain (ciphertext key iv)
  ;; identical to encryption — CTR is symmetric
  (des-ctr-encrypt-plain ciphertext key iv))
