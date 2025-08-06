;; tls-prf-sha384.lisp

(load "~/clocc/src/ssl/hmac-sha384.lisp") ; Adjust path

(defun tls-prf-sha384 (secret label seed length)
  "TLS PRF using HMAC-SHA384, per RFC 5246 section 5"
  (let* ((label+seed (concatenate '(vector (unsigned-byte 8))
                                  label seed))
         (output (make-array length :element-type '(unsigned-byte 8)))
         (a label+seed)
         (pos 0))
    ;; Generate enough output using iterative HMAC: P_hash
    (loop while (< pos length) do
      (setf a (words64-to-bytes (hmac-sha384 secret a))) ; A(i)
      (let ((block (words64-to-bytes (hmac-sha384 secret
                                (concatenate '(vector (unsigned-byte 8)) a label+seed)))))
        (loop for byte across block
              while (< pos length)
              do (setf (aref output pos) byte
                       pos (+ pos 1)))))
    output))
