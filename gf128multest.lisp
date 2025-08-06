(defun gf128-mul (x y)
  (let ((res 0)
        (R #xE1000000000000000000000000000000)
        (mask #xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF))
    (dotimes (i 128)
      (when (logbitp (- 127 i) y)
        (setf res (logxor (logand res mask) x)))
      (setf res (logand res mask)) ;; ✨ constrain res to 128 bits
      (setf x (if (logbitp 0 x)
                  (logand (logxor (ash x -1) R) mask)
                  (logand (ash x -1) mask)))
      (setf x (logand x mask)))
    res))

;; Convert 16-byte vector to bignum
(defun block->int (block)
  "Converts 128-bit block to bignum."
  (reduce (lambda (acc byte)
            (logior (ash acc 8) byte))
          block
          :initial-value 0))

;; Convert bignum to 16-byte vector
(defun int->block (n)
  "Converts bignum to 128-bit block (vector of bytes)."
  (let ((vec (make-array 16 :element-type '(unsigned-byte 8))))
    (dotimes (i 16)
      (setf (aref vec (- 15 i)) (ldb (byte 8 (* i 8)) n)))
    vec))

(defun gf128mul-spec (x y)
  (let ((res 0)
        (R #xE1000000000000000000000000000000)
        (mask #xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF))
    (dotimes (i 128)
      ;; Check if current bit in y is set (high to low)
      (when (logbitp (- 127 i) y)
	;; right shift
	(when (plusp (ldb (byte 1 1) x)) ;; Check if previous LSB was 1
	  (setf x (if (logbitp 0 x)
		      (logxor (ash x -1) R)
		      (ash x -1))))))
    (setf x (logand x mask))
    (setf res x)
    res))

(defun gf128mul-spec (x y)
  (let ((res 0)
        (R #xE1000000000000000000000000000000)
        (mask #xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF))
    (dotimes (i 128)
      (when (logbitp (- 127 i) y)
        (setf res (logxor (logand res mask) x)))
      (setf res (logand res mask)) ;; ✨ constrain res to 128 bits
      (setf x (if (logbitp 0 x)
                  (logand (logxor (ash x -1) R) mask)
                  (logand (ash x -1) mask)))
      (setf x (logand x mask)))
    res))


(defun test-gf128mul-spec1 ()
  (let* ((x #x00000000000000000000000000000001)
	 (y #x00000000000000000000000000000001)
	 (mask #xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)
         (result (logand (gf128mul-spec x y) mask)))
    (format t "result   = ~{~2,'0X~}~%" (coerce (int->block result) 'list))))

(defun test-gf128mul-spec2 ()
  (let* ((x #xE1000000000000000000000000000000)
	(y #x00000000000000000000000000000001)
	(result (int->block (gf128mul-spec x y))))
    (format t "result   = ~{~2,'0X~}~%" (coerce result 'list))))

(defun gf128-inc32 (x)
  "Increment the least significant 32 bits of block x"
  (let ((low32 (ldb (byte 32 0) x))
        (high96 (ldb (byte 96 32) x)))
    (setf low32 (mod (+ low32 1) (expt 2 32)))
    (logior (ash high96 32) low32)))

(defun reverse-128-bit-int (x)
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

(defun gf128mul-ghash (H block)
  (let ((res 0)
        (R #xE1000000000000000000000000000000)
        (mask #xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF))
    (dotimes (i 128)
      (when (logbitp (- 127 i) block)
        (setf res (logxor (logand res mask) H)))
      (setf res (logand res mask)) ;; ✨ constrain res to 128 bits
      (setf H (if (logbitp 0 H)
                  (logand (logxor (ash H -1) R) mask)
                  (logand (ash H -1) mask)))
      (setf H (logand H mask)))
    res))

(defun byte->bits (byte)
  (loop for i from 7 downto 0 collect (ldb (byte 1 i) byte)))

(defun block->bitlist (block)
  ;; Accepts a vector of 16 bytes and returns 128 bits as a vector
  (let ((bitlist (make-array 128 :element-type '(unsigned-byte 1))))
    (loop for i from 0 below 16 do
      (loop for j from 0 below 8 do
        (setf (aref bitlist (+ (* i 8) j))
              (ldb (byte 1 (- 7 j)) (aref block i)))))
    bitlist))

(defun test-gf128mul-ghash1 ()
  (let* ((H #x00000000000000000000000000000001)
	(block #x00000000000000000000000000000001)
	(result (gf128mul-spec H block)))
    (format t "~%Result   = ~32,'0X~%" result)
    (format t "Expected = 00000000000000000000000000000001~%")
    (int->block result)))

(defun test-gf128mul-ghash2 ()
  (let* ((H #xE1000000000000000000000000000000)
	(block #x00000000000000000000000000000001)
	 (result (gf128mul-spec H block)))
    
    (format t "~%Result   = ~32,'0X~%" result)
    (format t "Expected = E1000000000000000000000000000000~%")
    (int->block result)))

(defun test-gf128mul-ghash3 ()
    (let* ((H #xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)
	   (block #x7a43ec1d9c0a5a78a0b16533a6213cab)
	   ;; multiply as GHASH expects
	   (result (gf128mul-spec H block)))
    
      (format t "~%Result   = ~32,'0X~%" result)
      (format t "Expected = D3E039B9DC59C2550B6636B9E0EBBA58~%")
      (int->block result)))

#|
(defun test-gf128mul-ghash3 ()
  (let* ((H-bytes (make-array 16 :element-type '(unsigned-byte 8) :initial-element #xFF))
         (block-bytes (make-array 16 :element-type '(unsigned-byte 8) :initial-element #xFF))
         (H (block->int H-bytes))  ;; assuming block->int is defined elsewhere
         (result (gf128mul-ghash H (block->int block-bytes))))
    (format t "~%Result   = ~32,'0X~%" result)
    (format t "Expected = D3E039B9DC59C2550B6636B9E0EBBA58~%")
    (int->block result)))
|#

;; Expected result #(13 161 137 173 254 164 254 28 53 30 192 60 41 80 131 192)
(defun test-gf128mul-ghash4 ()
  (let* ((H #x7CB681CD037B6D137A95F4DB99C48351)
	(block #x7A43EC1D9C0A5A78A0B16533A6213CAB)
	 (result (gf128mul-spec H block)))
    (format t "~%Result   = ~32,'0X~%" result)
    (format t "Expected = 0DA189ADFEA4FE1C351EC03C295083C0~%")
    (int->block result)))

(test-gf128mul-spec1)
(test-gf128mul-spec2)
(test-gf128mul-ghash1)
(test-gf128mul-ghash2)
(test-gf128mul-ghash3)
(test-gf128mul-ghash4)
