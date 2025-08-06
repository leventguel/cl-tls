(defun build-finished-record (verify-data)
  "Constructs a Finished handshake record with computed verify_data."
  (let ((handshake-type #x14) ; Finished
        (length (length verify-data)))
    (coerce
     (append
      (list handshake-type
            (ldb (byte 8 16) length)
            (ldb (byte 8 8)  length)
            (ldb (byte 8 0)  length))
      (coerce verify-data 'list))
     '(vector (unsigned-byte 8)))))
