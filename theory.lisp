(defun xtime128 (b)
  "Multiply a 128-bit integer `b` by x in GF(2¹²⁸) with modular reduction."
  (if (logbitp 127 b) ; if overflow occurs (i.e. x¹²⁸ term appears)
      (logxor (ash b 1) #xE1000000000000000000000000000000)
      (ash b 1)))

(defun gf128-mul (a b)
  "Multiply two 128-bit integers a and b in GF(2¹²⁸) using bitwise polynomial multiplication and modular reduction."
  (let ((res 0)
        (R #xE1000000000000000000000000000000))
    (loop for i from 0 below 128 do
      (when (logbitp (- 127 i) b)       ; MSB-first scan
        (setf res (logxor res a)))
      (setf a (if (logbitp 127 a)       ; check for overflow
                  (logxor (ash a 1) R)  ; reduce modulo GHASH poly
                  (ash a 1))))
    res))
