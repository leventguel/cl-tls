(defun hex->bytes (hex)
  "Converts hex string to a vector of (unsigned-byte 8)."
  (let ((len (length hex)))
    (assert (evenp len))
    (let ((vec (make-array (/ len 2) :element-type '(unsigned-byte 8))))
      (loop for i from 0 below len by 2
            for b = (parse-integer hex :start i :end (+ i 2) :radix 16)
            for j from 0 do (setf (aref vec j) b))
      vec)))

(defun bytes->hex (vec)
  "Converts a vector of unsigned-byte 8 to a hex string."
  (with-output-to-string (s)
    (map nil (lambda (b) (format s "~2,'0X" b)) vec)))

(defun block->int (bytes)
  "Convert 16-byte vector to integer (big-endian)."
  (reduce (lambda (acc b) (logior (ash acc 8) b)) bytes :initial-value 0))

(defun block->int (block)
  (loop for b across block
        for i from 0
        sum (ash b (* 8 (- 15 i)))))

(defun block->int-le (bytes)
  "Convert 16-byte vector to integer (little-endian)."
  (reduce (lambda (acc b) (logior (ash acc 8) b))
          (reverse bytes)
          :initial-value 0))

(defun int->block (i)
  "Convert 128-bit integer to 16-byte big-endian vector."
  (let ((out (make-array 16 :element-type '(unsigned-byte 8))))
    (loop for idx from 15 downto 0 do
      (setf (aref out idx) (ldb (byte 8 0) i))
      (setf i (ash i -8)))
    out))

(defun int->block (int)
  (let ((block (make-array 16 :element-type '(unsigned-byte 8))))
    (dotimes (i 16)
      (setf (aref block i) (ldb (byte 8 (* 8 (- 15 i))) int)))
    block))

(defun int->block-le (i)
  "Convert 128-bit integer to 16-byte little-endian vector."
  (let ((out (make-array 16 :element-type '(unsigned-byte 8))))
    (loop for idx from 0 below 16 do
      (setf (aref out idx) (ldb (byte 8 0) i))
      (setf i (ash i -8)))
    out))

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

(defun chunk-blocks (vec &optional (block-size 16))
  "Splits a vector into a list of block-size chunks."
  (loop for i from 0 below (length vec) by block-size
        collect (subseq vec i (min (length vec) (+ i block-size)))))

(defun ghash (key-hex aad-hex ct-hex)
  "Computes GHASH(AAD || CT || len-block) with AES-128-derived H."
  (let* ((key-bytes (expand-key-128 (hex->bytes key-hex)))
	 (zero (make-array 16 :element-type '(unsigned-byte 8)
                          :initial-element 0))
         ;; You need AES-128 ECB encryption here (replace with your own)
         (H-bytes (aes128-ecb-encrypt zero key-bytes t))  ; returns 16-byte vector
         (H (block->int H-bytes))
         (AAD (hex->bytes aad-hex))
         (CT  (hex->bytes ct-hex))
         (len-block (int->block (logior
                                 (ash (* (length AAD) 8) 64)
				 (* (length CT) 8))))
         (blocks (append
		  (chunk-blocks AAD)
		  (chunk-blocks CT)
		  (list len-block)))
         (acc 0))
    
    (assert (= (length zero) 16))
    (assert (= (length H-bytes) 16))
    (assert (= (length len-block) 16))

    (format t "zero: ~X~%" zero)
    (format t "AAD: ~X~%" AAD)
    (format t "CT: ~X~%" CT)
    (format t "len-block: ~X~%" len-block)
    (format t "blocks: ~X~%" blocks)
    (terpri)

    (format t "H: ~a~%" (bytes->hex (int->block H)))
    
    (dolist (blk blocks)
      (let* ((blk-int (block->int blk))
             (xor (logxor acc blk-int)))
	(format t "Block: ~A~%" (bytes->hex blk))
	(format t "XOR with acc: ~X~%" xor)
	(setf acc (gf128-mul H xor))
	(format t "GHASH intermediate: ~A~%" (bytes->hex (int->block acc)))))))
    
(defun compute-aes-gcm-tag (key-hex iv-hex aad-hex ct-hex)
  "Computes the final AES-GCM tag as in Count = 0 test vector."
  (let* ((key-bytes (expand-key-128 (hex->bytes key-hex)))
         (zero-block (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0))
         (H-bytes (aes128-ecb-encrypt zero-block key-bytes t))
         (H (block->int H-bytes))
         (AAD (hex->bytes aad-hex))
         (CT  (hex->bytes ct-hex))
         (aad-len (* 8 (length AAD)))
         (ct-len (* 8 (length CT)))
         (len-block (int->block (logior (ash aad-len 64) ct-len)))
         (blocks (append
		  (chunk-blocks AAD)
		  (chunk-blocks CT)
		  (list len-block)))
         (acc 0))
    ;; GHASH accumulation
    (dolist (blk blocks)
      (setf acc (gf128-mul H (logxor acc (block->int blk)))))
    ;; Final AES encryption of IV || 0x00000001
    (let* ((iv-bytes (hex->bytes iv-hex))
           (counter-block (concatenate '(vector (unsigned-byte 8))
				       iv-bytes
				       #(#x0 #x0 #x0 #x01)))
           (ek (aes128-ecb-encrypt counter-block key-bytes t))
           (tag (map 'vector #'logxor ek (int->block acc))))
      (print "GHASH result:")
      (print (bytes->hex (int->block acc)))

      (print "Counter block:")
      (print (bytes->hex counter-block))
      
      (print "Encrypted counter block:")
      (print (bytes->hex ek))

      (print "Computed tag:")
      (print (bytes->hex tag))
      tag)))

;; Example usage (requires working AES-128-ECB):
(format t "~X~%" (ghash "77be63708971c4e240d1cb79e8d77feb" "7a43ec1d9c0a5a78a0b16533a6213cab" "")) ;; empty ciphertext
;;(format t "~{~2,'0X~}~%" (coerce (compute-aes-gcm-tag "77be63708971c4e240d1cb79e8d77feb" "e0e00f19fed7ba0136a797f3" "7a43ec1d9c0a5a78a0b16533a6213cab" "") 'list)) ; empty ciphertext
(bytes->hex (compute-aes-gcm-tag "77be63708971c4e240d1cb79e8d77feb" "e0e00f19fed7ba0136a797f3" "7a43ec1d9c0a5a78a0b16533a6213cab" "")) ;; empty ciphertext
