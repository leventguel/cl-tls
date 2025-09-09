(defpackage :shared-utils
  (:use :cl)
  (:export :print-indented :print-indented-dynamic
	   :print-hex :words-to-bytes :words64-to-bytes :wordsn-to-bytes
	   :write-hex-lines :generate-random-data
	   :get-bit :set-bit :bits-equal-p :byte->bits :byte-to-bits :bits-to-byte
	   :byte-vector-to-bit-vector :bit-vector-to-byte-vector :valid-byte-vector-p :ensure-byte-vector
	   :ensure-bit-vector :xor-bytes :xor-blocks
	   :byte-vector-to-hex-string :hex-string-to-byte-vector
	   :bignum-to-minimal-hex :safe-hex-string-to-byte-vector
	   :bytes->hex :hex->bytes :byte-vector-to-integer :integer-to-byte-vector
	   :normalize-to-byte-vector
	   :bitstring-to-byte-vector
	   :string-to-bytes :split-into-blocks :revers-128bit-int :reverse-block))

(in-package :shared-utils)

(defun print-indented (label value &key (indent 12))
  (format t "~%~A~%" label)
  (format t "~vA: ~A~%" indent "" value))

(defun print-indented-dynamic (label value)
  (let ((indent (+ (length label) 2))) ; 2 for ": "
    (format t "~%~A~%" label)
    (format t "~vA: ~A~%" indent "" value)))

(defun print-hex (buf)
  (loop for byte across buf do
    (format t "0x~2,'0X " byte))
  (terpri))

;; 32bit
(defun words-to-bytes (words)
  (let ((bytes (make-array (* 4 (length words)) :element-type '(unsigned-byte 8))))
    (loop for i from 0 below (length words)
          for word = (aref words i)
          for base = (* i 4)
          do (setf (aref bytes (+ base 0)) (ldb (byte 8 24) word)
                   (aref bytes (+ base 1)) (ldb (byte 8 16) word)
                   (aref bytes (+ base 2)) (ldb (byte 8 8) word)
                   (aref bytes (+ base 3)) (ldb (byte 8 0) word)))
    bytes))

;; 64bit
(defun words64-to-bytes (words)
  (let ((bytes (make-array (* 8 (length words)) :element-type '(unsigned-byte 8))))
    (loop for i from 0 below (length words)
          for word = (aref words i)
          for base = (* i 8)
          do (loop for j from 0 below 8
                   for shift = (* 8 (- 7 j))
                   do (setf (aref bytes (+ base j))
                            (ldb (byte 8 shift) word))))
    bytes))

;; word-size bit
(defun wordsn-to-bytes (words word-size)
  "Converts a vector of unsigned-byte N words to a byte vector."
  (let ((bytes (make-array (* word-size (length words)) :element-type '(unsigned-byte 8))))
    (loop for i from 0 below (length words)
          for word = (aref words i)
          for base = (* i word-size)
          do (loop for j from 0 below word-size
                   for shift = (* 8 (- (1- word-size) j))
                   do (setf (aref bytes (+ base j))
                            (ldb (byte 8 shift) word))))
    bytes))

;; hex text
(defun write-hex-lines (bytes filename)
  (with-open-file (out filename :direction :output :if-exists :supersede)
    (loop for i from 0 below (length bytes) by 16
          for chunk = (subseq bytes i (min (+ i 16) (length bytes)))
          do (format out "~4,'0X  " i)
             (loop for b across chunk do (format out "~2,'0X " b))
             (terpri out))))

(defun generate-random-data (length)
  (let ((random-bytes (make-array length :element-type '(unsigned-byte 8))))
    (dotimes (i length)
      (setf (aref random-bytes i) (random 256)))
    random-bytes))


;; ─────────────────────────────
;; Bit Utilities
;; ─────────────────────────────
(defun get-bit (vector bit-index)
  "Gets bit at absolute bit-index from vector."
  (let* ((byte-index (floor bit-index 8))
         (bit-pos (- 7 (mod bit-index 8)))
         (byte (aref vector byte-index)))
    (ldb (byte 1 bit-pos) byte)))

(defun set-bit (vector bit-index value)
  "Sets bit at absolute bit-index in vector to value (0 or 1)."
  (let* ((byte-index (floor bit-index 8))
         (bit-pos (- 7 (mod bit-index 8)))
         (byte (aref vector byte-index)))
    (setf (aref vector byte-index)
          (dpb value (byte 1 bit-pos) byte))))

(defun bits-equal-p (v1 v2 bit-count)
  (loop for i from 0 below bit-count
        always (= (get-bit v1 i) (get-bit v2 i))))

(defun byte->bits (byte)
  (loop for i from 7 downto 0 collect (ldb (byte 1 i) byte)))

(defun byte-to-bits (byte)
  (let ((bits (make-array 8 :element-type 'fixnum)))
    (dotimes (j 8)
      (setf (aref bits j)
            (if (logbitp (- 7 j) byte) 1 0)))
    bits))

(defun bits-to-byte (bits)
  (let ((byte 0))
    (dotimes (j 8)
      (setf byte
            (logior byte
                    (ash (aref bits j) (- 7 j)))))
    byte))

(defun byte-vector-to-bit-vector (bytes)
  "Convert a vector of bytes to a vector of bits."
  (let ((bit-vector (make-array (* (length bytes) 8) :element-type '(unsigned-byte 1))))
    (loop for i from 0 below (length bytes)
          for byte = (aref bytes i)
          do (loop for j from 0 below 8
                   do (setf (aref bit-vector (+ (* i 8) j))
                            (ldb (byte 1 (- 7 j)) byte))))
    bit-vector))

(defun bit-vector-to-byte-vector (bits)
  "Convert a bit-vector to a byte-vector (8 bits per byte)."
  (let* ((len (length bits))
         (byte-count (/ len 8))
         (bytes (make-array byte-count :element-type '(unsigned-byte 8))))
    (loop for i from 0 below byte-count
          for byte = 0
          do (loop for j from 0 below 8
                   for bit = (aref bits (+ (* i 8) j))
                   do (setf byte (+ (ash byte 1) bit)))
             (setf (aref bytes i) byte))
    bytes))

(defun valid-byte-vector-p (vec)
  (and (vectorp vec)
       (every (lambda (x) (typep x '(unsigned-byte 8))) vec)))

(defun ensure-byte-vector (x)
  (cond
    ((valid-byte-vector-p x) (copy-seq x))
    ((stringp x) (map 'vector #'char-code x))
    ((and (listp x) (every (lambda (y) (typep y '(unsigned-byte 8))) x))
     (coerce x '(vector (unsigned-byte 8))))
    (t (error "Cannot convert ~A to byte vector" (type-of x)))))

(defun ensure-bit-vector (x)
  (if (bit-vector-p x) x (byte-vector-to-bit-vector x)))

;; xor bytes
(defun xor-bytes (a b)
  "XORs two byte vectors of equal length."
  (let ((len (length a)))
    (coerce (loop for i from 0 below len
                  collect (logxor (aref a i) (aref b i)))
            '(vector (unsigned-byte 8)))))

(defun xor-blocks (a b)
  (map '(vector (unsigned-byte 8)) #'logxor (ensure-byte-vector a) (ensure-byte-vector b)))

(defun byte-vector-to-hex-string (vec)
  "Converts a vector of unsigned-byte N to a hex string, where N ∈ {8, 16, 32, 64}."
  (with-output-to-string (s)
    (loop for elem across vec
          do (cond
               ((typep elem '(unsigned-byte 8))
                (format s "~2,'0X" elem))
               ((typep elem '(unsigned-byte 16))
                (loop for shift from 8 downto 0 by 8
                      do (format s "~2,'0X" (ldb (byte 8 shift) elem))))
               ((typep elem '(unsigned-byte 32))
                (loop for shift from 24 downto 0 by 8
                      do (format s "~2,'0X" (ldb (byte 8 shift) elem))))
               ((typep elem '(unsigned-byte 64))
                (loop for shift from 56 downto 0 by 8
                      do (format s "~2,'0X" (ldb (byte 8 shift) elem))))
               (t (error "Unsupported element type: ~A" (type-of elem)))))))

(defun byte-vector-to-hex-string (vec)
  "Converts a vector of unsigned-byte N elements to a hex string."
  (with-output-to-string (s)
    (loop for elem across vec
          for width = (cond
                        ((typep elem '(unsigned-byte 8)) 1)
                        ((typep elem '(unsigned-byte 16)) 2)
                        ((typep elem '(unsigned-byte 32)) 4)
                        ((typep elem '(unsigned-byte 64)) 8)
                        (t (error "Unsupported element type: ~A" (type-of elem))))
          do (loop for shift from (* 8 (1- width)) downto 0 by 8
                   do (format s "~2,'0X" (ldb (byte 8 shift) elem))))))

(defun byte-vector-to-hex-string (vec &optional (width-in-bytes nil))
  "Converts a vector of integers to a hex string.
If WIDTH-IN-BYTES is provided, each element is padded to that width.
Otherwise, width is inferred from the element's type or value."
  (with-output-to-string (s)
    (loop for elem across vec
          for width = (or width-in-bytes
                          (cond
                            ((typep elem '(unsigned-byte 8)) 1)
                            ((typep elem '(unsigned-byte 16)) 2)
                            ((typep elem '(unsigned-byte 32)) 4)
                            ((typep elem '(unsigned-byte 64)) 8)
                            (t (ceiling (integer-length elem) 8)))) ; fallback for bignums
          do (loop for shift from (* 8 (1- width)) downto 0 by 8
                   do (format s "~2,'0X" (ldb (byte 8 shift) elem))))))

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


(defun bignum-to-minimal-hex (num)
  (let* ((bits (integer-length num))
         (bytes (ceiling bits 8)))
    (with-output-to-string (s)
      (loop for shift from (* 8 (1- bytes)) downto 0 by 8
            do (format s "~2,'0X" (ldb (byte 8 shift) num))))))

(defun safe-hex-string-to-byte-vector (s)
  (let ((clean (string-trim '(#\Space #\Tab #\Newline #\Return) s)))
    (if (or (string= clean "")
            (oddp (length clean)))
        (error "Malformed hex string: ~A" clean)
        (hex-string-to-byte-vector clean))))

(defun bytes->hex (vec)
  (byte-vector-to-hex-string vec))

(defun hex->bytes (hex)
  "Converts hex string to a vector of (unsigned-byte 8)."
  (let ((len (length hex)))
    (assert (evenp len))
    (let ((vec (make-array (/ len 2) :element-type '(unsigned-byte 8))))
      (loop for i from 0 below len by 2
            for b = (parse-integer hex :start i :end (+ i 2) :radix 16)
            for j from 0 do (setf (aref vec j) b))
      vec)))

(defun byte-vector-to-integer (vec &optional (element-width 8))
  "Converts a vector of unsigned-byte N elements (big-endian) into an integer.
   Assumes each element is element-width bits wide.
   Supports 8, 16, 32, 64, and arbitrary widths."
  (let ((byte-width (ceiling element-width 8)))
    (reduce (lambda (acc elem)
              (+ (* acc (expt 256 byte-width)) elem))
            vec
            :initial-value 0)))

(defun integer-to-byte-vector (n &optional (size 8))
  "Convert integer N to a vector of unsigned 8-bit bytes (big-endian).
   Pads or truncates to SIZE bytes."
  (check-type n integer)
  (if size
      ;; Fixed-size padded version
      (let ((bytes (make-array size :element-type '(unsigned-byte 8))))
        (dotimes (i size)
          (setf (aref bytes (- size i 1)) (logand #xFF (ash n (- (* i 8))))))
        bytes)
      ;; Minimal-length version
      (loop for i from (1- (integer-length n)) downto 0 by 8
            collect (ldb (byte 8 i) n) into bytes
            finally (return (coerce bytes 'vector)))))

(defun normalize-to-byte-vector (input &optional size)
  "Converts input (hex string, integer, or byte vector) to a byte vector of SIZE."
  (cond
    ((stringp input)
     (let ((vec (hex-string-to-byte-vector input)))
       (if size
           (subseq
	    (concatenate 'vector
			 (make-array (- size (length vec))
				     :element-type '(unsigned-byte 8)
				     :initial-element 0)
			 vec)
	    0 size)
           vec)))
    ((integerp input)
     (integer-to-byte-vector input size))
    ((typep input '(vector (unsigned-byte 8)))
     (if size
         (subseq
	  (concatenate 'vector
		       (make-array (- size (length input))
				   :element-type '(unsigned-byte 8)
				   :initial-element 0)
		       input)
	  0 size)
         input))
    (t (error "Unsupported input type: ~A" (type-of input)))))

(defun bitstring-to-byte-vector (bitstr)
  "Converts a string of bits (e.g. '1110') to a packed byte vector."
  (let* ((clean (string-trim '(#\Space #\Tab #\Return #\Newline) bitstr))
         (len (length clean))
         (byte-len (ceiling len 8))
         (vec (make-array byte-len :element-type '(unsigned-byte 8))))
    (dotimes (i len)
      (let* ((bit (if (char= (char clean i) #\1) 1 0))
             (byte-idx (floor i 8))
             (bit-pos (- 7 (mod i 8))))
        (setf (aref vec byte-idx)
              (dpb bit (byte 1 bit-pos) (aref vec byte-idx)))))
    vec))

(defun string-to-bytes (str)
  (map 'vector #'char-code str))

(defun split-into-blocks (data &optional (block-size 16))
  "Splits byte vector into list of block-sized vectors."
  (loop for i from 0 below (length data) by block-size
        collect (subseq data i (min (length data) (+ i block-size)))))

#|
(defun aes-cbc-encrypt-ironclad (plaintext key iv)
"Encrypts plaintext using AES-128-CBC. Requires Ironclad."
(let ((ctx (ironclad:make-cipher :aes :mode :cbc :key key :iv iv)))
(ironclad:encrypt-sequence ctx plaintext)))
|#

(defun reverse-128bit-int (x)
  (let ((result 0))
    (dotimes (i 16)
      (setf result
            (logior
             (ash result 8)
             (ldb (byte 8 (* i 8)) x))))
    result))

(defun reverse-block (block)
  (let ((reversed (make-array 16 :element-type '(unsigned-byte 8))))
    (dotimes (i 16)
      (setf (aref reversed i) (aref block (- 15 i))))
    reversed))
