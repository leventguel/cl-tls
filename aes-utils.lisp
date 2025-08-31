(defpackage :tls-aes-utils
  (:use :cl :shared-utils)
  (:export :pad-blocks :length-block :build-ghash-blocks :inc-counter
	   :block->int :int->block :int->block-le :block->int-le :int->block-64be
	   :pad16 :pad-right :chunk-blocks :pad-blocks :chunk-all :truncate-tag
	   :print-state-grid :zero-extend-block :block->bitlist :gf128-inc32))

(in-package :tls-aes-utils)

;; ─────────────────────────────
;; Layout Conversion Utilities
;; ─────────────────────────────

(defun int->block-64be (int)
  (let ((block (make-array 8 :element-type '(unsigned-byte 8))))
    (dotimes (i 8)
      (setf (aref block i) (ldb (byte 8 (* 8 (- 7 i))) int)))
    block))

(defun int->block-64be (n)
  "Converts integer to 8-byte big-endian block."
  (let ((bytes (make-array 8 :element-type '(unsigned-byte 8))))
    (dotimes (i 8)
      (setf (aref bytes (- 7 i)) (ldb (byte 8 (* i 8)) n)))
    bytes))

(defun pad-blocks (bytes)
  "Pads input to 16-byte block boundary."
  (let* ((len (length bytes))
         (pad-len (mod (- 16 (mod len 16)) 16))
         (full (concatenate '(vector (unsigned-byte 8)) bytes
                            (make-array pad-len :element-type '(unsigned-byte 8)
                                        :initial-element 0)))
         (blocks '()))
    (loop for i from 0 below (length full) by 16
          do (push (subseq full i (+ i 16)) blocks))
    (nreverse blocks)))

(defun length-block (aad-len-in-bits ct-len-in-bits)
  (concatenate '(vector (unsigned-byte 8))
               (int->block-64be aad-len-in-bits)
               (int->block-64be ct-len-in-bits)))

(defun build-ghash-blocks (aad ct &optional aad-len ct-len)
  "Returns list of padded blocks and final length block. Lengths in bytes."
  (let ((aad-len (or aad-len (length aad)))
        (ct-len (or ct-len (length ct))))
    (append (pad-blocks aad)
            (pad-blocks ct)
            (list (length-block (* 8 aad-len) (* 8 ct-len))))))

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

;; Convert 16-byte vector to bignum
(defun block->int (block)
  "Converts 128-bit block to bignum."
  (reduce (lambda (acc byte)
            (logior (ash acc 8) byte))
          block
          :initial-value 0))

(defun int->block (int)
  (let ((block (make-array 16 :element-type '(unsigned-byte 8))))
    (dotimes (i 16)
      (setf (aref block i) (ldb (byte 8 (* 8 (- 15 i))) int)))
    block))

;; Convert bignum to 16-byte vector
(defun int->block (n)
  "Converts bignum to 128-bit block (vector of bytes)."
  (let ((vec (make-array 16 :element-type '(unsigned-byte 8))))
    (dotimes (i 16)
      (setf (aref vec (- 15 i)) (ldb (byte 8 (* i 8)) n)))
    vec))

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

(defun chunk-blocks (vec &optional (block-size 16))
  "Splits a vector into a list of block-size chunks."
  (loop for i from 0 below (length vec) by block-size
        collect (subseq vec i (min (length vec) (+ i block-size)))))

(defun pad-blocks (vec)
  (let ((blocks (chunk-blocks vec)))
    (if (zerop (mod (length vec) 16))
        blocks
        (append (subseq blocks 0 (- (length blocks) 1))
                (list (pad16 (car (last blocks))))))))

(defun chunk-all (vec &optional (size 16))
  (loop for i from 0 below (length vec) by size
        collect (subseq vec i (min (+ i size) (length vec)))))

(defun truncate-tag (tag bits)
  (subseq tag 0 (/ bits 8)))

(defun print-state-grid (state title)
  (format t "~%~A~%" title)
  (dotimes (r 4)
    (loop for c from 0 to 3
          do (format t "~2,'0X " (aref state (+ (* r 4) c))))
    (terpri)))

(defun zero-extend-block (data &optional (target-size 16))
  "Zero-extends DATA to target SIZE (default 16 bytes). Pads with #x00 on the right."
  (check-type data (vector (unsigned-byte 8)))
  (let ((pad-len (- target-size (length data))))
    (if (< pad-len 0)
        (error "Input too long (~D bytes), cannot extend to ~D" (length data) target-size)
        (concatenate '(vector (unsigned-byte 8))
                     data
                     (make-array pad-len :element-type '(unsigned-byte 8)
                                 :initial-element 0)))))

(defun block->bitlist (block)
  ;; Accepts a vector of 16 bytes and returns 128 bits as a vector
  (let ((bitlist (make-array 128 :element-type '(unsigned-byte 1))))
    (loop for i from 0 below 16 do
      (loop for j from 0 below 8 do
        (setf (aref bitlist (+ (* i 8) j))
              (ldb (byte 1 (- 7 j)) (aref block i)))))
    bitlist))

(defun gf128-inc32 (x)
  "Increment the least significant 32 bits of block x"
  (let ((low32 (ldb (byte 32 0) x))
        (high96 (ldb (byte 96 32) x)))
    (setf low32 (mod (+ low32 1) (expt 2 32)))
    (logior (ash high96 32) low32)))
