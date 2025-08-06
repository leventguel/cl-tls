(load "util.lisp")

(defun mock-client-key-exchange ()
  (let ((dummy (generate-random-data 48)))  ; Premaster-like mock
    (let ((length (length dummy)))
      (coerce
       (append
        (list #x10   ; Handshake type: ClientKeyExchange
              (ldb (byte 8 16) length)
              (ldb (byte 8 8) length)
              (ldb (byte 8 0) length))
        (coerce dummy 'list))
       '(vector (unsigned-byte 8))))))
