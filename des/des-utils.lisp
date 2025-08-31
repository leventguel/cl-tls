(defpackage :des-utils
  (:use :cl :shared-utils)
  (:export :byte-vector-to-string :string-to-byte-vector :string-to-hex 
	   :hex-string-to-byte-vector :hex-to-string :byte-vector-to-hex-string :int-to-byte-vector
	   :int-to-bit-vector :bit-vector-to-int :check-for-vec-type
	   :assert-bit-vector :ensure-bit-length :ensure-bit-value :ensure-bit-table
	   :bit-vector-of-length-p :byte-vector-p :des-block-p :valid-des-input-p
	   :left-shift :split-block :split-key :split-into-6bit-chunks :split-into-blocks
	   :permutation-p :sequencep :check-block-size :shift-buffer-bit :increment-counter :chunk-vector
	   :byte-vector-to-bitstream :bitstream-to-byte-vector :read-file-as-string :write-string-to-file
	   :ede-call :ede-process))

(in-package :des-utils)

(defun byte-vector-to-string (bytes)
  "Convert a byte vector to a string using UTF-8 decoding."
  (coerce (map 'list #'code-char bytes) 'string))

(defun byte-vector-to-string (bytes)
  (map 'string #'code-char bytes))

(defun string-to-byte-vector (str)
  "Convert a string to a vector of bytes using UTF-8 encoding."
  (map 'vector #'char-code str))

(defun string-to-hex (str)
  (format nil "~{~2,'0X~}" (coerce (string-to-byte-vector str) 'list)))

(defun hex-to-string (hex)
  (byte-vector-to-string (hex-string-to-byte-vector hex)))

(defun int-to-byte-vector (n width)
  "Convert integer N into a bit vector of length WIDTH (most significant bit first)."
  (let ((bytes (make-array width :element-type 'vector)))
    (dotimes (i width)
      (setf (aref bytes i) (ldb (byte 8 (- width i 1)) n)))
    bytes))

(defun int-to-bit-vector (n width)
  "Convert integer N into a bit vector of length WIDTH (most significant bit first)."
  (let ((bits (make-array width :element-type 'bit)))
    (dotimes (i width)
      (setf (aref bits i) (ldb (byte 1 (- width i 1)) n)))
    bits))

(defun bit-vector-to-int (bits)
  "Convert a bit vector to an integer."
  (reduce (lambda (acc bit) (+ (* acc 2) bit)) bits :initial-value 0))

(defun check-for-vec-type (vec)
  (format t "Type: ~A, Length: ~A~%" (array-element-type vec) (length vec)))

(defun assert-bit-vector (vec)
  "Asserts that VEC is a bit-vector (element-type '(unsigned-byte 1))."
  (assert (bit-vector-p vec) () "Expected a bit-vector, got ~A" (type-of vec)))

(defun ensure-bit-length (vec expected-length)
  "Assert that VEC is a bit-vector of EXPECTED-LENGTH."
  (ensure-bit-vector vec)
  (assert (= (length vec) expected-length)
          () "Expected length ~D, got ~D" expected-length (length vec)))

(defun ensure-bit-value (vec)
  "Assert that every value in VEC is either 0 or 1."
  (ensure-bit-vector vec)
  (assert (every (lambda (b) (member b '(0 1))) vec)
          () "Bit-vector contains non-bit values: ~A" vec))

(defun ensure-bit-table (table max-position)
  "Assert that TABLE is a proper permutation over bit positions."
  (assert (vectorp table)
          () "Permutation table must be a vector, got ~A" (type-of table))
  (assert (every (lambda (x)
                   (and (integerp x)
                        (>= x 1)
                        (<= x max-position)))
                 table)
          () "Permutation table contains invalid positions: ~A" table))

(defun bit-vector-of-length-p (vec len)
  (and (bit-vector-p vec) (= (length vec) len)))

(defun byte-vector-p (vec)
  (and (vectorp vec)
       (equal (array-element-type vec) '(unsigned-byte 8))))

(defun des-block-p (vec)
  (bit-vector-of-length-p vec 64)) ; for 64-bit blocks

(defun valid-des-input-p (vec)
  (and (bit-vector-p vec)
       (= (length vec) 64)
       (every (lambda (b) (member b '(0 1))) vec)))

(defun left-shift (bits n)
  "Circular left shift of a bit vector by n positions."
  (let ((len (length bits)))
    (concatenate 'vector
                 (subseq bits n len)
                 (subseq bits 0 n))))

(defun split-block (block)
  "Split a 64-bit block into left and right 32-bit halves."
  (values
   (subseq block 0 32)   ; Left half
   (subseq block 32 64)) ; Right half
  )

(defun split-key (key56)
  "Split a 56-bit key into C0 and D0 (28 bits each)."
  (values
   (subseq key56 0 28)   ; C0
   (subseq key56 28 56)) ; D0
  )

(defun split-into-6bit-chunks (bits)
  "Split a 48-bit vector into 8 chunks of 6 bits each."
  (unless (= (length bits) 48)
    (error "Expected 48-bit input, got ~A bits" (length bits)))
  (let ((chunks (make-array 8)))
    (dotimes (i 8)
      (setf (aref chunks i)
            (subseq bits (* i 6) (+ (* i 6) 6))))
    chunks))

(defun permutation-p (table max-value)
  "Check if TABLE is a valid permutation of values from 1 to MAX-VALUE.
Allows duplicates only if explicitly intended (e.g., expansion table)."
  (and (every (lambda (x) (and (integerp x) (<= 1 x max-value))) table)
       (<= (length (remove-duplicates table)) max-value)))

(defun check-block-size (data &optional (block-size 8))
  "Ensures DATA represents a multiple of BLOCK-SIZE bytes."
  (unless (or (stringp data) (bit-vector-p data))
    (let ((total-bytes
           (cond
             ((vectorp data) (length data)) ; flat byte vector
             ((listp data) (reduce #'+ data :key #'length)) ; list of vectors
             (t (error "Unsupported data type: ~A" (type-of data))))))
      (unless (zerop (mod total-bytes block-size))
	(error "Data must be a multiple of ~D bytes, got ~D" block-size total-bytes)))))

(defun sequencep (x)
  (typep x 'sequence))

(defun check-block-size (data &optional (block-size 8))
  "Check that data is either a flat sequence divisible by block-size,
   or a list of sequences all of length block-size."
  (cond
    ((and (listp data) (every #'sequencep data))
     (unless (every (lambda (block) (= (length block) block-size)) data)
       (error "Block size mismatch")))
    ((sequencep data)
     (unless (zerop (mod (length data) block-size))
       (error "Flat sequence length not divisible by block size")))
    (t
     (error "Invalid data format for block size check"))))

(defun shift-buffer-bit (buffer bit)
  (let* ((bit-list (loop for b across buffer append (loop for i from 7 downto 0 collect (ldb (byte 1 i) b))))
         (new-bits (append (subseq bit-list 1) (list bit)))
         (new-bytes (loop for i from 0 below (length new-bits) by 8
                          collect (reduce (lambda (acc b) (+ (* acc 2) b))
                                          (subseq new-bits i (+ i 8))))))
    (coerce new-bytes 'vector)))

(defun shift-buffer-bit (buffer bit)
  (let ((new-buffer (make-array (length buffer) :element-type '(unsigned-byte 1))))
    (loop for i from 0 below (- (length buffer) 1)
          do (setf (aref new-buffer i) (aref buffer (+ i 1))))
    (setf (aref new-buffer (- (length buffer) 1)) bit)
    new-buffer))

(defun increment-counter (counter)
  (let ((new (copy-seq counter)))
    (loop for i from (1- (length new)) downto 0
          do (incf (aref new i))
             (when (< (aref new i) 256) (return)))
    new))

(defun chunk-vector (vec block-size)
  (loop for i from 0 below (length vec) by block-size
        collect (subseq vec i (min (length vec) (+ i block-size)))))

(defun byte-vector-to-bitstream (bytes)
  "Convert a byte vector to a list of bits (0 or 1)."
  (loop for byte across bytes
        append (loop for i from 7 downto 0
                     collect (ldb (byte 1 i) byte))))

(defun bitstream-to-byte-vector (bits)
  "Convert a list of bits to a byte vector."
  (let ((byte-count (floor (length bits) 8)))
    (make-array byte-count
                :element-type '(unsigned-byte 8)
                :initial-contents
                (loop for i from 0 below (* byte-count 8) by 8
                      collect (reduce (lambda (acc bit)
                                        (+ (ash acc 1) bit))
                                      (subseq bits i (+ i 8)))))))

(defun read-file-as-string (path)
  "Read the entire contents of a file as a string."
  (with-open-file (in path :direction :input)
    (let ((contents (make-string (file-length in))))
      (read-sequence contents in)
      contents)))

(defun write-string-to-file (path str)
  "Write a string to a file, overwriting if it exists."
  (with-open-file (out path :direction :output :if-exists :supersede :if-does-not-exist :create)
    (write-string str out)))

(defun ede-call (fn data key &optional iv)
  (if iv
      (funcall fn data key iv)
      (funcall fn data key)))

(defun ede-process (mode-fn data key1 key2 &optional iv)
  (let* ((step1 (ede-call mode-fn data key1 iv))
         (step2 (ede-call mode-fn step1 key2 iv)))
    (ede-call mode-fn step2 key1 iv)))
