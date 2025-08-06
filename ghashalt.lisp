;; Carry-less multiply and reduce modulo ghash polynomial
(defun gf128-mul (x y)
  "GHASH multiplication with correct bit ordering and polynomial reduction."
  (let ((z 0)
	(R #xE1000000000000000000000000000000))
    (dotimes (i 128)
      ;; If y bit i (from MSB to LSB) is set, XOR x into z                                                      
      (when (logbitp (- 127 i) y)
	(setf z (logxor z x)))
      ;; Shift x and reduce if MSB was set before shift                                                         
      (let ((msb-set (logbitp 127 x)))
	(setf x (ash x 1))
	(when msb-set
          (setf x (logxor x R)))))
    z))

(defun block->int (block)
  "Convert 16-byte block to bignum (MSB first)."
  (reduce (lambda (acc byte)
            (logior (ash acc 8) byte))
          block
          :initial-value 0))

(defun int->block (n)
  "Convert bignum to 16-byte block (MSB first)."
  (let ((vec (make-array 16 :element-type '(unsigned-byte 8))))
    (dotimes (i 16)
      (setf (aref vec (- 15 i)) (ldb (byte 8 (* i 8)) n)))
    vec))

(defun ghash (h blocks)
  "Reference GHASH implementation with full tracing."
  (let ((y 0)
        (h-int (block->int h)))
    (dolist (block blocks)
      (let ((x (block->int block)))
        (format t "~%📦 Block: ~X~%" x)
        (format t "🔁 Y before XOR: ~X~%" y)
        (format t "⤷ XOR → ~X~%" (logxor y x))
        (setf y (gf128-mul h-int (logxor y x)))
        (format t "🔚 Y after GHASH step: ~X~%" y)))
    (int->block y)))
