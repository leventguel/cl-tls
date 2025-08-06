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

(defparameter *x* #x7CB681CD037B6D137A95F4DB99C48351)
(defparameter *y* #x7A43EC1D9C0A5A78A0B16533A6213CAB)

(defparameter *product* (gf128-mul *x* *y*))

(format t "x is: ~a~%" *x*)
(format t "y is: ~a~%" *y*)
(format t "product: ~a~%" *product*)

