(defpackage :tls-aes256
  (:use :cl :shared-utils :tls-aes-utils)
  (:export :expand-key-256
	   :aes256-ecb-encrypt-block :aes256-ecb-encrypt :aes256-ecb-decrypt-block :aes256-ecb-decrypt
           :aes256-cbc-encrypt-block :aes256-cbc-encrypt :aes256-cbc-decrypt-block :aes256-cbc-decrypt
	   :aes256-ctr-encrypt :aes256-ctr-decrypt
	   :aes256-ofb-encrypt :aes256-ofb-decrypt
	   :aes256-cfb-xcrypt :aes256-cfb-encrypt :aes256-cfb-decrypt
	   :aes256-cfb8-xcrypt :aes256-cfb8-encrypt :aes256-cfb8-decrypt
	   :aes256-cfb1-xcrypt :aes256-cfb1-encrypt :aes256-cfb1-decrypt))

(in-package :tls-aes256)

;;; AES S-box
;; 2D Matrix version of the sbox
(defparameter *aes-sbox-matrix*
  (make-array '(16 16) :element-type '(unsigned-byte 8)
	      :initial-contents
	      '((#x63 #x7C #x77 #x7B #xF2 #x6B #x6F #xC5 #x30 #x01 #x67 #x2B #xFE #xD7 #xAB #x76)
		(#xCA #x82 #xC9 #x7D #xFA #x59 #x47 #xF0 #xAD #xD4 #xA2 #xAF #x9C #xA4 #x72 #xC0)
		(#xB7 #xFD #x93 #x26 #x36 #x3F #xF7 #xCC #x34 #xA5 #xE5 #xF1 #x71 #xD8 #x31 #x15)
		(#x04 #xC7 #x23 #xC3 #x18 #x96 #x05 #x9A #x07 #x12 #x80 #xE2 #xEB #x27 #xB2 #x75)
		(#x09 #x83 #x2C #x1A #x1B #x6E #x5A #xA0 #x52 #x3B #xD6 #xB3 #x29 #xE3 #x2F #x84)
		(#x53 #xD1 #x00 #xED #x20 #xFC #xB1 #x5B #x6A #xCB #xBE #x39 #x4A #x4C #x58 #xCF)
		(#xD0 #xEF #xAA #xFB #x43 #x4D #x33 #x85 #x45 #xF9 #x02 #x7F #x50 #x3C #x9F #xA8)
		(#x51 #xA3 #x40 #x8F #x92 #x9D #x38 #xF5 #xBC #xB6 #xDA #x21 #x10 #xFF #xF3 #xD2)
		(#xCD #x0C #x13 #xEC #x5F #x97 #x44 #x17 #xC4 #xA7 #x7E #x3D #x64 #x5D #x19 #x73)
		(#x60 #x81 #x4F #xDC #x22 #x2A #x90 #x88 #x46 #xEE #xB8 #x14 #xDE #x5E #x0B #xDB)
		(#xE0 #x32 #x3A #x0A #x49 #x06 #x24 #x5C #xC2 #xD3 #xAC #x62 #x91 #x95 #xE4 #x79)
		(#xE7 #xC8 #x37 #x6D #x8D #xD5 #x4E #xA9 #x6C #x56 #xF4 #xEA #x65 #x7A #xAE #x08)
		(#xBA #x78 #x25 #x2E #x1C #xA6 #xB4 #xC6 #xE8 #xDD #x74 #x1F #x4B #xBD #x8B #x8A)
		(#x70 #x3E #xB5 #x66 #x48 #x03 #xF6 #x0E #x61 #x35 #x57 #xB9 #x86 #xC1 #x1D #x9E)
		(#xE1 #xF8 #x98 #x11 #x69 #xD9 #x8E #x94 #x9B #x1E #x87 #xE9 #xCE #x55 #x28 #xDF)
		(#x8C #xA1 #x89 #x0D #xBF #xE6 #x42 #x68 #x41 #x99 #x2D #x0F #xB0 #x54 #xBB #x16))))

(defparameter *aes-inv-sbox-matrix*
  (let ((inv (make-array '(16 16) :element-type '(unsigned-byte 8))))
    (loop for row from 0 to 15 do
      (loop for col from 0 to 15 do
        (let* ((val (aref *aes-sbox-matrix* row col))
               (inv-row (floor val 16))
               (inv-col (mod val 16)))
          (setf (aref inv inv-row inv-col) (+ (* row 16) col)))))
    inv))

(defun sbox-lookup (byte)
  (let ((row (ash byte -4))
        (col (logand byte #x0F)))
    (check-type byte (unsigned-byte 8))
    (aref *aes-sbox-matrix* row col)))

;;; Round constants
(defparameter *rcon*
  (make-array 14 :element-type '(unsigned-byte 8)
              :initial-contents '(#x01 #x02 #x04 #x08 #x10 #x20 #x40 #x80 #x1B #x36 #x6C #xD8 #xAB #x4D)))

;; ─────────────────────────────
;; AES Transformations
;; ─────────────────────────────
(defun rotate (lst n)
  "Rotates a list left by n elements."
  (append (subseq lst n) (subseq lst 0 n)))

(defun sub-bytes-matrix (state)
  "SubBytes transform; input/output are row-major vectors."
   (map 'vector #'sbox-lookup state))

;; 1d only
(defun inv-sub-bytes (state)
  (map 'vector (lambda (b) (aref *aes-inv-sbox-matrix* b)) state))

(defun inv-sub-byte (byte)
  "Applies inverse SubBytes using 2D inverse S-box matrix."
  (aref *aes-inv-sbox-matrix*
        (floor byte 16)
        (mod byte 16)))

(defun inv-sub-bytes (state)
  "Applies inverse SubBytes to all bytes in a state vector."
  (map 'vector #'inv-sub-byte state))

(defun shift-rows (state)
  "ShiftRows transform; input/output are row-major."
  (let ((cm state))
    (dotimes (r 4)
      (let ((row (loop for c from 0 to 3 collect (aref cm (+ (* c 4) r)))))
        (let ((shifted (rotate row r)))
          (dotimes (c 4)
            (setf (aref cm (+ (* c 4) r)) (nth c shifted))))))
    cm))

(defun shift-rows (state)
  "Applies AES ShiftRows to a 16-byte column-major state."
  (let ((result (make-array 16 :element-type '(unsigned-byte 8))))
    (loop for row from 0 to 3 do
      (loop for col from 0 to 3 do
        (let* ((src-col (mod (+ col row) 4))
               (src-idx (+ (* src-col 4) row))
               (dst-idx (+ (* col 4) row)))
          (setf (aref result dst-idx) (aref state src-idx)))))
    result))

(defun inv-shift-rows (state)
  "Undo AES ShiftRows on a 16-byte column-major state."
  (let ((result (make-array 16 :element-type '(unsigned-byte 8))))
    (loop for row from 0 to 3 do
      (loop for col from 0 to 3 do
        (let* ((src-col (mod (- col row) 4))
               (src-idx (+ (* src-col 4) row))
               (dst-idx (+ (* col 4) row)))
          (setf (aref result dst-idx) (aref state src-idx)))))
    result))

(defun xtime (b)
  (logand (if (>= b #x80)
              (logxor (ash b 1) #x1B)
              (ash b 1))
          #xFF))

(defun gf-mul (a b)
  "Multiply bytes a and b in GF(2⁸)."
  (let ((res 0))
    (loop for i from 0 below 8 do
	  (when (logbitp i b)
            (setf res (logxor res a)))
	  (setf a (xtime a)))
    res))

(defparameter *gf-2*
  (make-array 256 :initial-contents (loop for i below 256 collect (gf-mul 2 i))))
(defparameter *gf-3*
  (make-array 256 :initial-contents (loop for i below 256 collect (gf-mul 3 i))))

(defun mix-column (col)
  "Mix one AES column (4 bytes)."
  (vector
   (logxor (aref *gf-2* (aref col 0))
           (aref *gf-3* (aref col 1))
           (aref col 2)
           (aref col 3))
   (logxor (aref col 0)
           (aref *gf-2* (aref col 1))
           (aref *gf-3* (aref col 2))
           (aref col 3))
   (logxor (aref col 0)
           (aref col 1)
           (aref *gf-2* (aref col 2))
           (aref *gf-3* (aref col 3)))
   (logxor (aref *gf-3* (aref col 0))
           (aref col 1)
           (aref col 2)
           (aref *gf-2* (aref col 3)))))

(defun mix-columns (state)
  "AES MixColumns; input/output are row-major vectors of 16 bytes.
Internally converts to column-major for mixing, then returns to row-major."
  (let ((cm (copy-seq state)))
    ;; Process each of the 4 columns independently
    (dotimes (c 4)
      (let* ((offset (* c 4))
             ;; Create a fresh copy of the column to avoid accidental mutation
             (column (subseq cm offset (+ offset 4)))
             (mixed  (mix-column column)))
        ;; Insert mixed column back into position
        (replace cm mixed :start1 offset)))
    ;; Return to row-major layout
    cm))

(defun inv-mix-column (col)
  "Inverse MixColumns for one column."
  (vector
   (logxor (gf-mul #x0E (aref col 0))
           (gf-mul #x0B (aref col 1))
           (gf-mul #x0D (aref col 2))
           (gf-mul #x09 (aref col 3)))
   (logxor (gf-mul #x09 (aref col 0))
           (gf-mul #x0E (aref col 1))
           (gf-mul #x0B (aref col 2))
           (gf-mul #x0D (aref col 3)))
   (logxor (gf-mul #x0D (aref col 0))
           (gf-mul #x09 (aref col 1))
           (gf-mul #x0E (aref col 2))
           (gf-mul #x0B (aref col 3)))
   (logxor (gf-mul #x0B (aref col 0))
           (gf-mul #x0D (aref col 1))
           (gf-mul #x09 (aref col 2))
           (gf-mul #x0E (aref col 3)))))

(defun inv-mix-columns (state)
  "Applies inverse MixColumns to a 16-byte state (column-major)."
  (let ((result (copy-seq state)))
    (dotimes (c 4)
      (let* ((offset (* c 4))
             (column (subseq result offset (+ offset 4)))
             (mixed (inv-mix-column column)))
        (replace result mixed :start1 offset)))
    result))

(defun round-key (expanded round)
  "Extracts the 16-byte round key from expanded schedule."
  (loop for i from (* round 16) below (+ (* round 16) 16)
        collect (aref expanded i) into bytes
        finally (return (coerce bytes 'vector))))

(defun add-round-key (state round-key)
  "Byte-wise XOR using indexed access."
  (let ((out (make-array 16 :element-type '(unsigned-byte 8))))
    (loop for i from 0 below 16
          do (setf (aref out i) (logxor (aref state i) (aref round-key i))))
    out))

;; ─────────────────────────────
;; Key Expansion
;; ─────────────────────────────

(defun rot-word (w)
  (vector (aref w 1) (aref w 2) (aref w 3) (aref w 0)))

(defun sub-word (w)
  (map 'vector #'sbox-lookup w))

(defun expand-key-256 (key)
  "Expand a 32-byte AES-256 key into 60 4-byte words (240 bytes total)."
  (let* ((Nk 8)
         (Nr 14)
         (Nb 4)
         ;; Rcon: round constants (14 rounds for AES-256)
         (rcon #(#x01 #x02 #x04 #x08 #x10 #x20 #x40 #x80 #x1B #x36 #x6C #xD8 #xAB #x4D))
         ;; Preallocate words array of 60 4-byte vectors
         (words (make-array (* Nb (+ Nr 1))
                            :element-type '(simple-array (unsigned-byte 8) (4))
                            :initial-element (make-array 4 :element-type '(unsigned-byte 8))))
         ;; Force deep copy of key
         (key-bytes (coerce key 'list)))

    ;; Load key into words[0..7]
    (dotimes (i Nk)
      (setf (aref words i)
            (make-array 4 :element-type '(unsigned-byte 8)
                        :initial-contents (subseq key-bytes (* i 4) (+ (* i 4) 4)))))

    ;; Expand the key
    (loop for i from Nk below (* Nb (+ Nr 1)) do
      (let ((temp (make-array 4 :element-type '(unsigned-byte 8))))
        ;; Copy previous word safely
        (dotimes (j 4)
          (setf (aref temp j) (aref (aref words (- i 1)) j)))

        ;; Apply transformation every Nk words
        (when (= (mod i Nk) 0)
          (let ((rot (make-array 4 :element-type '(unsigned-byte 8)))
                (sub (make-array 4 :element-type '(unsigned-byte 8))))
            ;; RotWord
            (setf (aref rot 0) (aref temp 1))
            (setf (aref rot 1) (aref temp 2))
            (setf (aref rot 2) (aref temp 3))
            (setf (aref rot 3) (aref temp 0))
            ;; SubWord
            (dotimes (j 4)
              (setf (aref sub j) (sbox-lookup (aref rot j))))
            ;; Rcon XOR
            (let ((rcon-index (1- (truncate i Nk))))
              (when (< rcon-index (length rcon))
                (let ((rcon-byte (aref rcon rcon-index)))
                  (dotimes (j 4)
                    (setf (aref temp j)
                          (logxor (aref sub j) (if (= j 0) rcon-byte 0)))))))))

        ;; Extra SubWord every 4th word after Nk (AES-256 only)
        (when (= (mod i Nk) 4)
          (dotimes (j 4)
            (setf (aref temp j) (sbox-lookup (aref temp j)))))

        ;; XOR with word[i - Nk]
        (let ((new-word (make-array 4 :element-type '(unsigned-byte 8))))
          (dotimes (j 4)
            (setf (aref new-word j)
                  (logxor (aref temp j) (aref (aref words (- i Nk)) j))))
          (setf (aref words i) new-word))))

    ;; Flatten into 240-byte vector
    (let ((out (make-array 240 :element-type '(unsigned-byte 8))))
      (dotimes (i 60)
        (dotimes (j 4)
          (setf (aref out (+ (* i 4) j)) (aref (aref words i) j))))
      out)))

;; ─────────────────────────────
;; AES Block Encryption
;; ─────────────────────────────
(defun pad-pkcs7 (data block-size &optional force-pad)
  "PKCS#7 padding. Pads only if needed, unless force-pad is true."
  (let* ((r (mod (length data) block-size))
         (pad-len (cond ((or (= r 0) force-pad) block-size)
                        (t (- block-size r))))
         (pad-byte pad-len)
         (padding (make-array pad-len :element-type '(unsigned-byte 8)
                              :initial-element pad-byte)))
    (concatenate '(vector (unsigned-byte 8)) data padding)))

(defun aes256-ecb-encrypt-block (plaintext key-or-expanded &optional (raw nil) (block-size 16))
  "Encrypts one block. Pads input with PKCS#7 if it's not exactly block-size."
  (let* ((input (if (and raw (/= (mod (length plaintext) block-size) 0))
		    ;; Unpadded plaintext which is not block-size has to be padded in raw mode
		    ;; otherwise it won't work
		    (pad-pkcs7 plaintext block-size)
		    (if (= (mod (length plaintext) block-size) 0)
			plaintext
			(pad-pkcs7 plaintext block-size))))
	 (key-size 32)
         (expanded-key
	  (if (= (length key-or-expanded) key-size)
	      (expand-key-256 (copy-seq key-or-expanded))
	   key-or-expanded))
         (state    (add-round-key (copy-seq input) (round-key expanded-key 0))))

    ;; Optional warning if raw mode input was not block-aligned
    (when (and raw (/= (mod (length plaintext) block-size) 0))
      (format t "~%⚠️ Raw mode input was not block-aligned — PKCS#7 padding applied.~%"))

    ;; Main rounds
    (dotimes (round 13)
      (setf state (sub-bytes-matrix state))
      (setf state (shift-rows state))
      (setf state (mix-columns state))
      (setf state (add-round-key state (round-key expanded-key (1+ round)))))
    
    ;; Final round (no MixColumns)
    (setf state (sub-bytes-matrix state))
    (setf state (shift-rows state))
    (setf state (add-round-key state (round-key expanded-key 14)))
    state))

(declaim (ftype function trace-aes256-ecb-encrypt-block))

(defun aes256-ecb-encrypt (plaintext key-or-expanded &optional (raw nil) (verbose nil) (block-size 16))
  "Encrypts plaintext of any length using AES-256 ECB.
Each block is padded by aes256-ecb-encrypt-block if needed."
  (let* ((padded
	  (if (and raw (/= (mod (length plaintext) block-size) 0))
	      ;; Unpadded plaintext which is not block-size has to be padded in raw mode
	      ;; otherwise it won't work
	      (pad-pkcs7 plaintext block-size)
	      (if (= (mod (length plaintext) block-size) 0)
		  plaintext
		  (pad-pkcs7 plaintext block-size))))
         (expanded-key (expand-key-256 key-or-expanded))
         (ciphertext (make-array 0 :element-type '(unsigned-byte 8))))

    (when (and raw (/= (mod (length plaintext) block-size) 0))
      (format t "~%⚠️ Raw mode input was not block-aligned — padding applied.~%"))

    ;; 🔍 Show full plaintext before encryption
    (when verbose
      (format t "~%🔓 Original Plaintext:~%")
      (loop for i from 0 below (length plaintext) by block-size
            for block = (subseq plaintext i (min (+ i block-size) (length plaintext)))
            for index = (/ i block-size)
            do (format t "Block ~D: ~{~2,'0X~^ ~}~%" index (coerce block 'list)))
      
      (format t "~%🔓 Padded Plaintext:~%")
      (loop for i from 0 below (length padded) by block-size
            for block = (subseq padded i (+ i block-size))
            for index = (/ i block-size)
            do (format t "Block ~D: ~{~2,'0X~^ ~}~%" index (coerce block 'list))))
    
    (loop for i from 0 below (length padded) by block-size
          for block = (subseq padded i (+ i block-size)) and index = (/ i block-size)
          do (setf ciphertext
                   (concatenate '(vector (unsigned-byte 8))
                                ciphertext
				(if verbose
				    (progn 
                                      (format t "~%=== Block ~D Encryption ===~%" index)
				      (trace-aes256-ecb-encrypt-block block expanded-key raw))
                                    (aes256-ecb-encrypt-block block expanded-key raw)))))
    ciphertext))

(defun trace-aes256-ecb-encrypt-block (plaintext key-or-expanded &optional (raw nil) (block-size 16))
  "Prints each transformation stage for one AES-256 ECB block encryption."
  (let* ((input
	  (if (and raw (/= (mod (length plaintext) block-size) 0))
	      ;; Unpadded plaintext which is not block-size has to be padded in raw mode
	      ;; otherwise it won't work
	      (pad-pkcs7 plaintext block-size)
	      (if (= (mod (length plaintext) block-size) 0)
		  plaintext
		  (pad-pkcs7 plaintext block-size))))
	 (key-size 32)
	 (expanded-key
	  (if (= (length key-or-expanded) key-size)
	      (expand-key-256 (copy-seq key-or-expanded))
	      key-or-expanded))
	 (state (copy-seq input)))
    
    (format t "~%🔓 Plaintext: ~{~2,'0X~^ ~}~%" (coerce state 'list))
    (format t "🔑 KeyAddition (Round 0): ")
    (setf state (add-round-key state (round-key expanded-key 0)))
    (format t "~{~2,'0X~^ ~}~%" (coerce state 'list))

    (dotimes (round 13)
      (format t "~%=== Round ~D ===~%" (1+ round))
      (setf state (sub-bytes-matrix state))
      (format t "🧬 SubBytes:   ~{~2,'0X~^ ~}~%" (coerce state 'list))

      (setf state (shift-rows state))
      (format t "🔄 ShiftRows:  ~{~2,'0X~^ ~}~%" (coerce state 'list))

      (setf state (mix-columns state))
      (format t "🔗 MixColumns: ~{~2,'0X~^ ~}~%" (coerce state 'list))

      (setf state (add-round-key state (round-key expanded-key (+ round 1))))
      (format t "🔐 AddRoundKey:~{~2,'0X~^ ~}~%" (coerce state 'list)))

    ;; Final Round (no MixColumns)
    (format t "~%=== Final Round ===~%")
    (setf state (sub-bytes-matrix state))
    (format t "🧬 SubBytes:   ~{~2,'0X~^ ~}~%" (coerce state 'list))

    (setf state (shift-rows state))
    (format t "🔄 ShiftRows:  ~{~2,'0X~^ ~}~%" (coerce state 'list))

    (setf state (add-round-key state (round-key expanded-key 14)))
    (format t "🔐 Final KeyAdd:~{~2,'0X~^ ~}~%" (coerce state 'list))

    (format t "~%🧱 Ciphertext: ~{~2,'0X~^ ~}~%" (coerce state 'list))
    ;; return final ciphertext
    state))

(defun trace-aes256-ecb-encrypt (plaintext key-or-expanded &optional (raw nil) (block-size 16))
  "Encrypts arbitrary-length plaintext in ECB mode with full per-block tracing and PKCS#7 padding."
  (let* ((padded
	  (if (and raw (/= (mod (length plaintext) block-size) 0))
	      ;; Unpadded plaintext which is not block-size has to be padded in raw mode
	      ;; otherwise it won't work
	      (pad-pkcs7 plaintext block-size)
	      (if (= (mod (length plaintext) block-size) 0)
		  plaintext
		  (pad-pkcs7 plaintext block-size))))
         (expanded-key (expand-key-256 (copy-seq key-or-expanded)))
         (ciphertext (make-array 0 :element-type '(unsigned-byte 8))))
    
    (loop for i from 0 below (length padded) by block-size
          for block = (subseq padded i (+ i block-size))
          for index = (/ i block-size)
          for encrypted = (progn
                            (format t "~%=== Block ~D ===~%" index)
                            (trace-aes256-ecb-encrypt-block block expanded-key raw))
          do (setf ciphertext
                   (concatenate '(vector (unsigned-byte 8)) ciphertext encrypted)))
    (format t "~%🧱 Final Full Ciphertext:~%")
    (dotimes (i (floor (length ciphertext) 16))
      (format t "~{~2,'0X~^ ~}~%" 
              (coerce (subseq ciphertext (* i 16) (+ (* i 16) 16)) 'list)))
    ciphertext))

;; ECB Decryption
(defun maybe-unpad-pkcs7 (data block-size)
  (let* ((pad-byte (aref data (1- (length data)))))
    (if (and (> pad-byte 0)
             (<= pad-byte block-size)
             (<= pad-byte (length data)))
        (let* ((pad-start (- (length data) pad-byte))
               (padding (subseq data pad-start)))
          (if (and (= (length padding) pad-byte)
                   (every (lambda (b) (= b pad-byte)) padding))
              (subseq data 0 pad-start)
              data))
        data))) ; If pad-byte is invalid, return data untouched

(defun aes256-ecb-decrypt-block (ct key-or-expanded &optional (raw nil) (block-size 16))
  "Decrypts a single AES-256 block. Unpads if PKCS#7 padding is detected."
  (let* ((key-size 32)
	(expanded-key
	(if (= (length key-or-expanded) key-size)
	    (expand-key-256 key-or-expanded)
	    key-or-expanded))
	(state (copy-seq ct)))
    ;; Initial round key
    (setf state (add-round-key state (round-key expanded-key 14)))

    ;; Rounds 13 → 1
    (dotimes (r 13)
      (let ((round (- 13 r)))
        (setf state (inv-shift-rows state))
        (setf state (inv-sub-bytes state))
        (setf state (add-round-key state (round-key expanded-key round)))
        (setf state (inv-mix-columns state))))

    ;; Final Round (0)
    (setf state (inv-shift-rows state))
    (setf state (inv-sub-bytes state))
    (setf state (add-round-key state (round-key expanded-key 0)))

    ;; Optional unpadding
    (if raw
	state
	(maybe-unpad-pkcs7 state block-size))))

(declaim (ftype function trace-aes256-ecb-decrypt-block))

(defun aes256-ecb-decrypt (ciphertext key-or-expanded &optional (raw nil) (verbose nil) (block-size 16))
  "Decrypts AES-256 ECB ciphertext with full per-block tracing and PKCS#7 unpadding."
  (let* ((expanded-key (expand-key-256 (copy-seq key-or-expanded)))
         (plaintext (make-array 0 :element-type '(unsigned-byte 8))))
    
    (loop for i from 0 below (length ciphertext) by block-size
          for block = (subseq ciphertext i (+ i block-size))
          for index = (floor i block-size)
          for decrypted = (if verbose
                              (progn
                                (format t "~%=== Block ~D Decryption ===~%" index)
                                (trace-aes256-ecb-decrypt-block block expanded-key raw))
                              (aes256-ecb-decrypt-block block expanded-key raw))
          do (setf plaintext
                   (concatenate '(vector (unsigned-byte 8)) plaintext decrypted)))
    
    ;; Remove PKCS#7 padding
    (if raw
	plaintext
	(let ((unpadded (maybe-unpad-pkcs7 plaintext block-size)))
	  (when verbose
	    (format t "~%🔓 Final Recovered Plaintext:~%")
	    (let ((len (length unpadded)))
	      (loop for i from 0 below len by block-size
		    for block = (subseq unpadded i (min (+ i block-size) len))
		    for index = (/ i block-size)
		    do (format t "Block ~D: ~{~2,'0X~^ ~}~%" index (coerce block 'list)))))
	  unpadded))))

(defun trace-aes256-ecb-decrypt-block (ct key-or-expanded &optional (raw nil) (block-size 16))
  "Trace AES-256 decryption stages for a single 16-byte ciphertext block."
  (let* ((key-size 32)
	(expanded-key
	(if (= (length key-or-expanded) key-size)
	    (expand-key-256 key-or-expanded)
	    key-or-expanded))
	(state (copy-seq ct)))
    (format t "~%🔐 Ciphertext: ~{~2,'0X~^ ~}~%" (coerce state 'list))
    (format t "🔑 Initial KeyAddition (Round 14): ")
    (setf state (add-round-key state (round-key expanded-key 14)))
    (format t "~{~2,'0X~^ ~}~%" (coerce state 'list))

    ;; Rounds 13 → 1
    (dotimes (r 13)
      (let ((round (- 13 r)))
        (format t "~%=== Round ~D ===~%" round)
        (setf state (inv-shift-rows state))
        (format t "🔄 InvShiftRows: ~{~2,'0X~^ ~}~%" (coerce state 'list))

        (setf state (inv-sub-bytes state))
        (format t "🧬 InvSubBytes:  ~{~2,'0X~^ ~}~%" (coerce state 'list))

        (setf state (add-round-key state (round-key expanded-key round)))
        (format t "🔑 KeyAddition:  ~{~2,'0X~^ ~}~%" (coerce state 'list))

        (setf state (inv-mix-columns state))
        (format t "🔗 InvMixColumn: ~{~2,'0X~^ ~}~%" (coerce state 'list))))

    ;; Final Round (0)
    (format t "~%=== Final Round (0) ===~%")
    (setf state (inv-shift-rows state))
    (format t "🔄 InvShiftRows: ~{~2,'0X~^ ~}~%" (coerce state 'list))

    (setf state (inv-sub-bytes state))
    (format t "🧬 InvSubBytes:  ~{~2,'0X~^ ~}~%" (coerce state 'list))

    (setf state (add-round-key state (round-key expanded-key 0)))
    (format t "🔑 Final KeyAdd: ~{~2,'0X~^ ~}~%" (coerce state 'list))

    (format t "~%🔓 Recovered Plaintext: ~{~2,'0X~^ ~}~%" (coerce state 'list))
    (if raw
	state
	(maybe-unpad-pkcs7 state block-size))))

(defun trace-aes256-ecb-decrypt (ciphertext key-or-expanded &optional (raw nil) (block-size 16))
  "Decrypts AES-256 ECB ciphertext with full per-block tracing and PKCS#7 unpadding."
  (let* ((expanded-key (expand-key-256 (copy-seq key-or-expanded)))
         (plaintext (make-array 0 :element-type '(unsigned-byte 8))))
    (loop for i from 0 below (length ciphertext) by block-size
          for block = (subseq ciphertext i (+ i block-size))
          for index = (floor i block-size)
          for decrypted = (progn
                            (format t "~%=== Block ~D Decryption ===~%" index)
                            (trace-aes256-ecb-decrypt-block block expanded-key raw))
          do (setf plaintext
                   (concatenate '(vector (unsigned-byte 8)) plaintext decrypted)))

    ;; Remove PKCS#7 padding
    (if raw
	plaintext
	(let ((unpadded (maybe-unpad-pkcs7 plaintext block-size)))
	  (format t "~%🔓 Final Recovered Plaintext:~%")
	  (dotimes (i (floor (length unpadded) 16))
            (format t "~{~2,'0X~^ ~}~%" 
                    (coerce (subseq unpadded (* i 16) (+ (* i 16) 16)) 'list)))
	  unpadded))))

(defun aes256-cbc-encrypt-block (block previous-ciphertext expanded-key)
  (aes256-ecb-encrypt-block
   (map 'vector #'logxor block previous-ciphertext)
   expanded-key
   t))

(defun aes256-cbc-encrypt (plaintext key iv &optional (raw nil) (block-size 16))
  "Encrypts plaintext using AES-256 in CBC mode with optional PKCS#7 padding."
  (let* ((padded (if raw plaintext (pad-pkcs7 plaintext block-size)))
         (expanded-key (expand-key-256 key))
         (ciphertext (make-array 0 :element-type '(unsigned-byte 8)))
         (previous-block iv))
    (loop for i from 0 below (length padded) by block-size
          for block = (subseq padded i (+ i block-size))
          for encrypted = (aes256-cbc-encrypt-block block previous-block expanded-key)
          do (setf ciphertext
                   (concatenate '(vector (unsigned-byte 8)) ciphertext encrypted)
              previous-block encrypted))
    ciphertext))

(defun aes256-cbc-decrypt-block (block previous-ciphertext expanded-key &optional (block-size 16))
  "Decrypts one CBC block by AES-256 ECB and XOR with previous ciphertext block."
  (let* ((decrypted (aes256-ecb-decrypt-block block expanded-key t block-size))
         (xored (map 'vector #'logxor decrypted previous-ciphertext)))
    xored))

(defun aes256-cbc-decrypt (ciphertext key iv &optional (raw nil) (block-size 16))
  "Decrypts AES-256 CBC ciphertext with optional PKCS#7 unpadding."
  (let* ((expanded-key (expand-key-256 key))
         (plaintext (make-array 0 :element-type '(unsigned-byte 8)))
         (previous-block iv))
    (loop for i from 0 below (length ciphertext) by block-size
          for block = (subseq ciphertext i (+ i block-size))
          for decrypted = (aes256-ecb-decrypt-block block expanded-key t block-size)
          for xored = (map 'vector #'logxor decrypted previous-block)
          do (setf plaintext
                   (concatenate '(vector (unsigned-byte 8)) plaintext xored)
              previous-block block))
    (if raw
        plaintext
        (maybe-unpad-pkcs7 plaintext block-size))))

(defun test-aes256-cbc ()
  (let* ((key #(0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15))
         (iv  #(0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0))
         (plaintext #(1 2 3 4 5 6 7 8 9 10))
         (ciphertext (aes256-cbc-encrypt plaintext key iv))
         (recovered  (aes256-cbc-decrypt ciphertext key iv)))
    (format t "~%CBC Test Result: ~A~%" (equalp plaintext recovered))
    (format t "Original:  ~{~2,'0X~^ ~}~%" (coerce plaintext 'list))
    (format t "Recovered: ~{~2,'0X~^ ~}~%" (coerce recovered 'list))))

(defun test-aes256-cbc-decrypt ()
  (let* ((key #(0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15))
         (iv  #(0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0))
         (plaintext #(1 2 3 4 5 6 7 8 9 10))
         (ciphertext (aes256-cbc-encrypt plaintext key iv))
         (expanded-key (expand-key-256 key))
         (recovered (make-array 0 :element-type '(unsigned-byte 8)))
         (previous-block iv))
    (loop for i from 0 below (length ciphertext) by 16
          for block = (subseq ciphertext i (+ i 16))
          for decrypted = (aes256-cbc-decrypt-block block previous-block expanded-key)
          do (setf recovered
                   (concatenate '(vector (unsigned-byte 8)) recovered decrypted)
              previous-block block))
    (setf recovered (maybe-unpad-pkcs7 recovered 16))
    (format t "~%CBC Decrypt Block Test Result: ~A~%" (equalp plaintext recovered))
    (format t "Original:  ~{~2,'0X~^ ~}~%" (coerce plaintext 'list))
    (format t "Recovered: ~{~2,'0X~^ ~}~%" (coerce recovered 'list))))

(defparameter *plaintext64*
  (make-array 64 :element-type '(unsigned-byte 8)
              :initial-contents
              (loop for i from 0 below 64 collect (mod (+ i 1) 256))))

(defun test-aes256-cbc-64 ()
  (let* ((key #(0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15))
         (iv  #(0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0))
         (plaintext *plaintext64*)
         (ciphertext (aes256-cbc-encrypt plaintext key iv))
         (recovered  (aes256-cbc-decrypt ciphertext key iv)))
    (format t "~%CBC 64-byte Test Result: ~A~%" (equalp plaintext recovered))
    (format t "Original:~%")
    (loop for i from 0 below (length plaintext) by 16
          do (format t "~{~2,'0X~^ ~}~%" (coerce (subseq plaintext i (+ i 16)) 'list)))
    (format t "Recovered:~%")
    (loop for i from 0 below (length recovered) by 16
          do (format t "~{~2,'0X~^ ~}~%" (coerce (subseq recovered i (+ i 16)) 'list)))))

(defun test-nist-cbc-vector ()
  "NIST vectors assume no padding"
  (let* ((key (hex-string-to-byte-vector "80000000000000000000000000000000"))
         (iv  (hex-string-to-byte-vector "00000000000000000000000000000000"))
         (plaintext (hex-string-to-byte-vector "00000000000000000000000000000000"))
         (expected (hex-string-to-byte-vector "0EDD33D3C621E546455BD8BA1418BEC8"))
         (ciphertext (aes256-cbc-encrypt plaintext key iv t))) ; raw = t
    (format t "~%NIST CBC Vector Test: ~A~%" (equalp ciphertext expected))))

(defun increment-counter (counter)
  "Returns a new vector with the input counter incremented by 1 (mod 2^128)."
  (let ((result (copy-seq counter)))
    (loop for i from (1- (length result)) downto 0 do
      (let ((val (aref result i)))
        (cond
          ((= val 255)
           (setf (aref result i) 0))
          (t
           (setf (aref result i) (1+ val))
           (return)))))
    result))

(defun aes256-ctr-xcrypt (input key iv &optional (block-size 16))
  "Encrypts or decrypts the input using AES-256 in CTR mode with the initial counter IV."
  (let* ((expanded-key (expand-key-256 key))
         (output (make-array (length input) :element-type '(unsigned-byte 8)))
         (counter iv))
    (loop for i from 0 below (length input) by block-size do
      (let* ((chunk-size (min block-size (- (length input) i)))
             (block (subseq input i (+ i chunk-size)))
             (keystream (aes256-ecb-encrypt counter expanded-key t nil)))
        (dotimes (j chunk-size)
          (setf (aref output (+ i j))
                (logxor (aref block j) (aref keystream j))))
        (setf counter (increment-counter counter))))
    output))

(defun aes256-ctr-encrypt (plaintext key iv)
  (aes256-ctr-xcrypt plaintext key iv))

(defun aes256-ctr-decrypt (ciphertext key iv)
  (aes256-ctr-xcrypt ciphertext key iv))

(defun aes256-ofb-xcrypt (input key iv &optional (block-size 16))
  "Encrypts or decrypts the input using AES in OFB mode."
  (let* ((key-length (length key))
         (expanded-key
          (cond
            ((= key-length 32) (expand-key-256 key))
            (t (error "Unsupported AES key length: ~A" key-length))))
         (output (make-array (length input) :element-type '(unsigned-byte 8)))
         (feedback-block iv)) ; Start with IV
    (loop for i from 0 below (length input) by block-size do
      (let* ((chunk-size (min block-size (- (length input) i)))
             (block (subseq input i (+ i chunk-size)))
             (keystream (aes256-ecb-encrypt feedback-block expanded-key t nil)))
        ;; XOR input with keystream
        (dotimes (j chunk-size)
          (setf (aref output (+ i j))
                (logxor (aref block j) (aref keystream j))))
        ;; Update feedback block for next round
        (setf feedback-block keystream)))
    output))

(defun aes256-ofb-encrypt (plaintext key iv)
  ;; Feedback loop using ECB encryption of previous ciphertext block
  (aes256-ofb-xcrypt plaintext key iv))

(defun aes256-ofb-decrypt (ciphertext key iv)
  ;; Same as encrypt but swaps roles of XOR input/output
  (aes256-ofb-xcrypt ciphertext key iv))

(defun aes256-cfb-xcrypt (input key iv &key decrypt)
  "Encrypts or decrypts using AES in CFB256 mode."
  (let* ((key-length (length key))
         (expanded-key
          (cond
            ((= key-length 32) (expand-key-256 key))
            (t (error "Invalid AES key size: ~A bytes" key-length))))
         (output (make-array (length input) :element-type '(unsigned-byte 8)))
         (block-size 16)
         (feedback iv)) ; feedback starts as IV
    (loop for i from 0 below (length input) by block-size do
      (let* ((chunk-size (min block-size (- (length input) i)))
             (block (subseq input i (+ i chunk-size)))
             (encrypted-feedback (aes256-ecb-encrypt feedback expanded-key t))
             (result (make-array chunk-size :element-type '(unsigned-byte 8))))
        ;; XOR plaintext/ciphertext with encrypted feedback
        (dotimes (j chunk-size)
          (setf (aref result j)
                (logxor (aref block j) (aref encrypted-feedback j)))
          (setf (aref output (+ i j)) (aref result j)))
        ;; Update feedback block
        (setf feedback (if decrypt block result))))
    output))

(defun aes256-cfb-encrypt (plaintext key iv)
  ;; Feedback loop using ECB encryption of previous ciphertext block
  (aes256-cfb-xcrypt plaintext key iv :decrypt nil))

(defun aes256-cfb-decrypt (ciphertext key iv)
  ;; Same as encrypt but swaps roles of XOR input/output
  (aes256-cfb-xcrypt ciphertext key iv :decrypt t))

(defun aes256-cfb8-xcrypt (input key iv &key decrypt)
  "Encrypts or decrypts using AES in CFB8 mode (byte-wise feedback)."
  (let* ((key-length (length key))
         (expanded-key
           (cond
             ((= key-length 32) (expand-key-256 key))
             (t (error "Invalid AES key size: ~A bytes" key-length))))
         (output (make-array (length input) :element-type '(unsigned-byte 8)))
         (feedback (copy-seq iv)))
    (loop for i from 0 below (length input) do
      (let* ((encrypted (aes256-ecb-encrypt feedback expanded-key t nil))
             (ks-byte (aref encrypted 0))
             (in-byte (aref input i))
             (out-byte (logxor in-byte ks-byte)))
        (setf (aref output i) out-byte)
        (setf feedback (concatenate '(vector unsigned-byte)
                                    (subseq feedback 1)
                                    (vector (if decrypt in-byte out-byte))))))
    output))

(defun aes256-cfb8-encrypt (plaintext key iv)
  ;; Feedback loop using ECB encryption of previous ciphertext block
  (aes256-cfb8-xcrypt plaintext key iv :decrypt nil))

(defun aes256-cfb8-decrypt (ciphertext key iv)
  ;; Same as encrypt but swaps roles of XOR input/output
  (aes256-cfb8-xcrypt ciphertext key iv :decrypt t))

(defun aes256-cfb1-xcrypt (input key iv &key decrypt)
  "Encrypts or decrypts using AES in CFB1 mode (bit-wise feedback)."
  (let* ((bit-length (* (length input) 8)) ; total bits
         (key-length (length key))
         (expanded-key
           (cond
             ((= key-length 32) (expand-key-256 key))
             (t (error "Invalid AES key size: ~A bytes" key-length))))
         (output (make-array (length input) :element-type '(unsigned-byte 8)))
         (feedback (copy-seq iv)))
    ;; Initialize output bits to 0
    (dotimes (i (length output)) (setf (aref output i) 0))
    ;; Process bit-by-bit
    (loop for i from 0 below bit-length do
      (let* ((encrypted (aes256-ecb-encrypt feedback expanded-key t nil))
             (keystream-bit (get-bit encrypted 0))
             (input-bit (get-bit input i))
             (result-bit (logxor input-bit keystream-bit)))
        ;; Set result bit
        (set-bit output i result-bit)
        ;; Update feedback
        (let ((feedback-bit (if decrypt input-bit result-bit)))
          ;; Shift feedback left by 1 bit and insert feedback-bit at end
          (loop for j from 0 below 127 do
            (set-bit feedback j (get-bit feedback (1+ j))))
          (set-bit feedback 127 feedback-bit))))
    output))

(defun aes256-cfb1-encrypt (plaintext key iv)
  ;; Feedback loop using ECB encryption of previous ciphertext block
  (aes256-cfb1-xcrypt plaintext key iv :decrypt nil))

(defun aes256-cfb1-decrypt (ciphertext key iv)
  ;; Same as encrypt but swaps roles of XOR input/output
  (aes256-cfb1-xcrypt ciphertext key iv :decrypt t))
