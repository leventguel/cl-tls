(defun inc-counter (block)
  "Increment last 32 bits of 16-byte vector as a big-endian counter."
  (let ((out (copy-seq block)))
    (loop for i from 15 downto 12 do
      (setf (aref out i)
            (ldb (byte 8 0)
                 (+ (aref out i)
                    (if (= i 15) 1 0))))
      (when (< (aref out i) 256)
	(return)))
    out))

(defun chunk-blocks (vec &optional (block-size 16))
  "Splits a vector into a list of block-size chunks."
  (loop for i from 0 below (length vec) by block-size
	collect (subseq vec i (min (length vec) (+ i block-size)))))

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

(defun ghash (h blocks)
  (let ((h-int (block->int h))
	(y 0))
    (dolist (block blocks)
      (setf y (gf128-mul h-int (logxor y (block->int block)))))
    (int->block y)))

(let* (
       ;; Convert hex strings to byte vectors
       (key (hex-string-to-byte-vector "77be63708971c4e240d1cb79e8d77feb"))
       (iv  (hex-string-to-byte-vector "e0e00f19fed7ba0136a797f3"))
       (aad (hex-string-to-byte-vector "7a43ec1d9c0a5a78a0b16533a6213cab"))
       (pt #())

       ;; Expand key + compute H
       (expanded-key (expand-key-128 key))
       (h (aes128-ecb-encrypt
           (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)
           expanded-key t nil))

       ;; Compute J₀
       (j0 (concatenate '(vector (unsigned-byte 8)) iv #(0 0 0 1)))

       ;; Encrypt plaintext using AES-CTR (J₀ + 1)
       ;; Note: PT is only one block here
       (ct (aes128-ecb-encrypt pt expanded-key (inc-counter j0)))

       ;; Construct GHASH blocks
       (len-block #(0 0 0 0 0 0 0 128 0 0 0 0 0 0 0 0)) ; 128 bits each for AAD and CT
       (ghash-input (list aad len-block))
       
       (s (ghash h ghash-input))

       ;; Compute tag
       (tag-base (aes128-ecb-encrypt j0 expanded-key t nil))

       (computed-tag (loop for i below 16 collect
                           (logxor (aref tag-base i) (aref s i))))
       
       (expected-tag (hex-string-to-byte-vector "209fcc8d3675ed938e9c7166709dd946"))

       ;; Compare tags
       )

  ;; Output
  (format t "~%🧪 GHASH blocks:~%")
  (loop for blk in ghash-input
        for idx from 0
        do (format t "  Block ~D: ~X~%" idx blk))

  (format t "~%🔐 H subkey: ~X~%" h)
  (format t "~% J₀: ~X~%" j0)
  (format t " last bit of j0: ~a~%" (ldb (byte 1 0) (aref j0 15)))
  (format t "~%📐 GHASH digest: ~X~%" s)
  (format t "~%🔄 Tag base (AES(K, J₀)): ~X~%" tag-base)
  (format t "~%🎯 Computed tag: ~X~%" computed-tag)
  (format t "~%📏 Expected tag: ~X~%" expected-tag)

  ;; Tag match check
  (if (equalp computed-tag expected-tag)
      (format t "~%✅ TAG MATCHES!~%")
      (format t "~%❌ TAG MISMATCH.~%")))
