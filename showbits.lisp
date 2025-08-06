(defun show-bits (value &optional (width 128))
  (format t "Bit Index (MSB → LSB):~%")
  (loop for i from (1- width) downto 0 do
       (format t "~A" (ldb (byte 1 i) value))
       (when (zerop (mod i 8)) (format t " ")))
  (terpri))

;; 🔍 Example usage
(show-bits #x80000000000000000000000000000001)
