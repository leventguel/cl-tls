;; generate-random-key.lisp

(defun os-random-bytes (length)
  "Read LENGTH random bytes from /dev/urandom."
  (let ((stream (open "/dev/urandom" :element-type '(unsigned-byte 8)))
        (buf (make-array length :element-type '(unsigned-byte 8))))
    (unwind-protect
         (progn 
           (read-sequence buf stream)
           buf) ; return the buffer not just the bytes read
      (close stream))))

(defun generate-random-key (length)
  "Generates a (vector (unsigned-byte 8)) of LENGTH random bytes."
  (let ((key (make-array length :element-type '(unsigned-byte 8))))
    (loop for i from 0 below length
          do (setf (aref key i) (random 256))) ; NOT cryptographically secure!
    key))

(defun weak-random-bytes (length)
  "NOT cryptographically secure—use only for testing."
  (make-array length
              :element-type '(unsigned-byte 8)
              :initial-contents
              (loop repeat length collect (random 256))))

(defun generate-key (length &optional (secure t))
  (if secure
      (os-random-bytes length)
      (weak-random-bytes length)))
