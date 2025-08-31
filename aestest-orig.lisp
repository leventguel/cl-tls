(defpackage :aes-test
  (:use :cl)
  (:export
   :*aes-sbox* :*rcon* :*gf-2* :*gf-3*
   :rotate :to-column-major :from-column-major :print-state-grid
   :hex-string-to-byte-vector :sub-bytes-matrix :shift-rows :xtime
   :gf-mul :mix-column :mix-columns :add-round-key :rot-word :safe-row-word
   :sub-word :safe-sub-word :expand-key-128 :round-key :aes-128-encrypt-block
   :run-test))

(in-package :aes-test)

;;; AES S-box
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

(defparameter *aes-sbox* nil)
;;(setf *aes-sbox* *aes-sbox-matrix*)

(defun sbox-lookup (byte)
  "Return AES S-box substitution for BYTE."
  (aref *aes-sbox-matrix* (ash byte -4) (logand byte #x0F));; only for 2D
  )

(defun sbox-lookup (byte)
  (let ((row (floor byte 16))
        (col (mod byte 16)))
    (aref *aes-sbox-matrix* row col)))

(defun sbox-lookup (byte)
  (let ((row (ash byte -4))
        (col (logand byte #x0F)))
    (check-type byte (unsigned-byte 8))
    (aref *aes-sbox-matrix* row col)))

#|
(defparameter *aes-sbox*
  #(#x63 #x7C #x77 #x7B #xF2 #x6B #x6F #xC5 #x30 #x01 #x67 #x2B #xFE #xD7 #xAB #x76
    #xCA #x82 #xC9 #x7D #xFA #x59 #x47 #xF0 #xAD #xD4 #xA2 #xAF #x9C #xA4 #x72 #xC0
    #xB7 #xFD #x93 #x26 #x36 #x3F #xF7 #xCC #x34 #xA5 #xE5 #xF1 #x71 #xD8 #x31 #x15
    #x04 #xC7 #x23 #xC3 #x18 #x96 #x05 #x9A #x07 #x12 #x80 #xE2 #xEB #x27 #xB2 #x75
    #x09 #x83 #x2C #x1A #x1B #x6E #x5A #xA0 #x52 #x3B #xD6 #xB3 #x29 #xE3 #x2F #x84
    #x53 #xD1 #x00 #xED #x20 #xFC #xB1 #x5B #x6A #xCB #xBE #x39 #x4A #x4C #x58 #xCF
    #xD0 #xEF #xAA #xFB #x43 #x4D #x33 #x85 #x45 #xF9 #x02 #x7F #x50 #x3C #x9F #xA8
    #x51 #xA3 #x40 #x8F #x92 #x9D #x38 #xF5 #xBC #xB6 #xDA #x21 #x10 #xFF #xF3 #xD2
    #xCD #x0C #x13 #xEC #x5F #x97 #x44 #x17 #xC4 #xA7 #x7E #x3D #x64 #x5D #x19 #x73
    #x60 #x81 #x4F #xDC #x22 #x2A #x90 #x88 #x46 #xEE #xB8 #x14 #xDE #x5E #x0B #xDB
    #xE0 #x32 #x3A #x0A #x49 #x06 #x24 #x5C #xC2 #xD3 #xAC #x62 #x91 #x95 #xE4 #x79
    #xE7 #xC8 #x37 #x6D #x8D #xD5 #x4E #xA9 #x6C #x56 #xF4 #xEA #x65 #x7A #xAE #x08
    #xBA #x78 #x25 #x2E #x1C #xA6 #xB4 #xC6 #xE8 #xDD #x74 #x1F #x4B #xBD #x8B #x8A
    #x70 #x3E #xB5 #x66 #x48 #x03 #xF6 #x0E #x61 #x35 #x57 #xB9 #x86 #xC1 #x1D #x9E
    #xE1 #xF8 #x98 #x11 #x69 #xD9 #x8E #x94 #x9B #x1E #x87 #xE9 #xCE #x55 #x28 #xDF
    #x8C #xA1 #x89 #x0D #xBF #xE6 #x42 #x68 #x41 #x99 #x2D #x0F #xB0 #x54 #xBB #x16))

;; for 1D only
(defun sbox-lookup (byte)
  (aref *aes-sbox* byte))
|#

;; for comparing 1D and 2D versions of the sboxes
(defun compare-sboxes ()
  (dotimes (i 256)
    (let* ((row (ash i -4))
           (col (logand i #x0F))
           (val2d (aref *aes-sbox-matrix* row col))
           (val1d (aref *aes-sbox* i))) ;; assuming you kept original flat version
      (unless (= val2d val1d)
        (format t "❌ Mismatch at index ~D: 1D=~D, 2D=~D~%" i val1d val2d)))))

;;; Round constants
;;(defparameter *rcon* #(1 2 4 8 16 32 64 128 27 54))

(defparameter *rcon*
  (make-array 11 :element-type '(unsigned-byte 8)
              :initial-contents '(#x01 #x02 #x04 #x08 #x10 #x20 #x40 #x80 #x1B #x36 #x6C)))

;; ─────────────────────────────
;; Layout Conversion Utilities
;; ─────────────────────────────

(defun rotate (lst n)
  "Rotates a list left by n elements."
  (append (subseq lst n) (subseq lst 0 n)))

(defun to-column-major (vec)
  "Convert 16-byte row-major vector to AES column-major layout."
  (let ((out (make-array 16 :element-type '(unsigned-byte 8))))
    (dotimes (r 4)
      (dotimes (c 4)
        (setf (aref out (+ (* c 4) r))
              (aref vec (+ (* r 4) c)))))
    out))

(defun from-column-major (vec)
  "Convert AES column-major vector back to row-major layout."
  (let ((out (make-array 16 :element-type '(unsigned-byte 8))))
    (dotimes (r 4)
      (dotimes (c 4)
        (setf (aref out (+ (* r 4) c))
              (aref vec (+ (* c 4) r)))))
    out))

(defun print-state-grid (state title)
  (format t "~%~A~%" title)
  (dotimes (r 4)
    (loop for c from 0 to 3
          do (format t "~2,'0X " (aref state (+ (* r 4) c))))
    (terpri)))

(defun print-state-grid-column-major (state title)
  (format t "~%~A~%" title)
  (dotimes (row 4)
    (loop for col from 0 to 3
          do (format t "~2,'0X " (aref state (+ (* col 4) row))))
    (terpri)))

(defun hex-string-to-byte-vector (hexstr)
  "Converts hex string to byte vector."
  (let ((len (/ (length hexstr) 2)))
    (let ((vec (make-array len :element-type '(unsigned-byte 8))))
      (loop for i from 0 below len do
            (setf (aref vec i) (parse-integer (subseq hexstr (* 2 i) (+ (* 2 i) 2)) :radix 16)))
      vec)))

(defun byte-vector-to-hex-string (vec)
  (format nil "~{~2,'0X~}" (coerce vec 'list)))

;; ─────────────────────────────
;; AES Transformations
;; ─────────────────────────────

(defun sub-bytes-matrix (state)
  "SubBytes transform; input/output are row-major vectors."
   (map 'vector #'sbox-lookup state))

(defun shift-rows (state)
  "ShiftRows transform; input/output are row-major."
  (let ((cm state))
    (dotimes (r 4)
      (let ((row (loop for c from 0 to 3 collect (aref cm (+ (* c 4) r)))))
        (let ((shifted (rotate row r)))
          (dotimes (c 4)
            (setf (aref cm (+ (* c 4) r)) (nth c shifted))))))
    cm))

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

(defun mix-columns (state)
   (let ((cm state))
     (dotimes (c 4)
       (let* ((offset (* c 4))
              (column (subseq cm offset (+ offset 4)))
              (mixed  (mix-column column)))
         (replace cm mixed :start1 offset)))
     cm))

(defun round-key (expanded round)
  "Returns the round key for given round (row-major)."
  (subseq expanded (* round 16) (+ (* round 16) 16)))

(defun round-key (expanded round)
  "Copies the 16-byte round key into a fresh vector."
  (let ((key (make-array 16 :element-type '(unsigned-byte 8))))
    (replace key expanded :start2 (* round 16))
    key))

(defun round-key (expanded round)
  "Extracts the 16-byte round key from expanded schedule."
  (loop for i from (* round 16) below (+ (* round 16) 16)
        collect (aref expanded i) into bytes
        finally (return (coerce bytes 'vector))))

(defun add-round-key (state round-key)
  "XOR each byte of the state with the round key; both row-major."
  (map 'vector #'logxor state round-key))

(defun add-round-key (state round-key)
  "XORs state and round key into a new vector."
  (map-into (make-array 16 :element-type '(unsigned-byte 8))
            #'logxor state round-key))

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

(defun safe-rot-word (w)
  (let ((wcopy (copy-seq w)))
    (vector (aref wcopy 1) (aref wcopy 2) (aref wcopy 3) (aref wcopy 0))))

(defun sub-word (w)
  (map 'vector #'sbox-lookup w))

(defun safe-sub-word (w)
  (let ((wcopy (copy-seq w)))
    (map 'vector #'sbox-lookup wcopy)))

(defun expand-key-128 (key)
  "Expand a 16-byte AES-128 key into 44 4-byte words (176 bytes total)."
  (let* ((Nk 4)
         (Nr 10)
         (Nb 4)
         ;; Rcon: round constants
         (rcon #(#x01 #x02 #x04 #x08 #x10 #x20 #x40 #x80 #x1B #x36))
         ;; Preallocate words array of 44 4-byte vectors
         (words (make-array (* Nb (+ Nr 1))
                            :element-type '(simple-array (unsigned-byte 8) (4))
			    :initial-element (make-array 4 :element-type '(unsigned-byte 8))))
         ;; Force deep copy of key
         (key-bytes (coerce key 'list)))
    
    ;; Load key into words[0..3]
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
            (let ((rcon-index (1- (truncate (/ i Nk)))))
              (when (< rcon-index (length rcon))
                (let ((rcon-byte (aref rcon rcon-index)))
                  (dotimes (j 4)
                    (setf (aref temp j)
                          (logxor (aref sub j) (if (= j 0) rcon-byte 0)))))))))

        ;; XOR with word[i - Nk]
        (let ((new-word (make-array 4 :element-type '(unsigned-byte 8))))
          (dotimes (j 4)
            (setf (aref new-word j)
                  (logxor (aref temp j) (aref (aref words (- i Nk)) j))))
          (setf (aref words i) new-word))))
    
    ;; Flatten into 176-byte vector
    (let ((out (make-array 176 :element-type '(unsigned-byte 8))))
      (dotimes (i 44)
        (dotimes (j 4)
          (setf (aref out (+ (* i 4) j)) (aref (aref words i) j))))
      out)))

;; ─────────────────────────────
;; AES Block Encryption
;; ─────────────────────────────

(defun checked-add-round-key (state key round)
  (print-state-grid state (format nil "🔍 Round ~D Pre-XOR State" round))
  (print-state-grid key (format nil "🔑 Round ~D Raw Key" round))
  (let ((out (add-round-key state key)))
    (print-state-grid out (format nil "🎯 Round ~D Post-XOR State" round))
    out))

(defun compare-layouts (state key)
  (dotimes (i 16)
    (format t "Byte ~D: State=~2,'0X Key=~2,'0X~%" i (aref state i) (aref key i))))

(defun aes-128-encrypt-block (plaintext key)
  "Encrypts 16-byte row-major plaintext with 16-byte key."
  (let* ((expanded (expand-key-128 (copy-seq key)))
         (state    (add-round-key (copy-seq plaintext) (round-key expanded 0))))
    (compare-layouts state key)
    ;; Main rounds
    (dotimes (round 9)
      (setf state (sub-bytes-matrix state))
      (setf state (shift-rows state))
      (setf state (mix-columns state))
      (setf state (add-round-key state (round-key expanded (1+ round)))))
    ;; Final round (no MixColumns)
    (setf state (sub-bytes-matrix state))
    (setf state (shift-rows state))
    (setf state (add-round-key state (round-key expanded 10)))
    (print-state-grid state "Final AES State")
    state))


;; ─────────────────────────────
;; Test Runner
;; ─────────────────────────────

;;; Test runner
(defun run-test ()
  "Runs AES-128 test vector and prints match result."
  (let* ((key-str "2b7e151628aed2a6abf7158809cf4f3c")
         (pt-str  "6bc1bee22e409f96e93d7e117393172a")
         (ct-str  "3ad77bb40d7a3660a89ecaf32466ef97")
         (key     (hex-string-to-byte-vector key-str))
         (pt      (hex-string-to-byte-vector pt-str))
         (expected (hex-string-to-byte-vector ct-str))
         (output   (aes-128-encrypt-block pt key)))
    (format t "~%🔒 AES Encryption Test~%")
    (format t "Plaintext: ~{~2,'0X~^ ~}~%" (coerce pt 'list))
    (format t "Key:       ~{~2,'0X~^ ~}~%" (coerce key 'list))
    (format t "Expected:  ~{~2,'0X~^ ~}~%" (coerce expected 'list))
    (format t "Output:    ~{~2,'0X~^ ~}~%" (coerce output 'list))
    (if (equalp output expected)
        (format t "✅ Match confirmed.~%")
        (progn
          (format t "❌ Mismatch detected.~%")
          (dotimes (i 16)
            (unless (equalp (aref output i) (aref expected i))
              (format t "Byte ~D mismatch: Expected ~2,'0X, got ~2,'0X~%"
                      i (aref expected i) (aref output i))))))))

;; To run the test:
;; (in-package :aes-test)
;; (run-test)
