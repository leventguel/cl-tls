(defpackage :aes-test
  (:use :cl :tls-aes-utils :tls-aes128)
  (:export :run-test))

(in-package :aes-test)

;; ─────────────────────────────
;; Test Runner
;; ─────────────────────────────

;;; Test runner
(defun run-test ()
  "Runs AES-128 test vector and prints match result."
  (let* ((key-str "2b7e151628aed2a6abf7158809cf4f3c")
         (pt-str  "6bc1bee22e409f96e93d7e117393172a")
         (ct-str  "3ad77bb40d7a3660a89ecaf32466ef97")
         (key     (hex-string-to-byte-vector key-str))
         (pt      (hex-string-to-byte-vector pt-str))
         (expected (hex-string-to-byte-vector ct-str))
         (output   (aes128-ecb-encrypt-block pt key)))
    (format t "~%🔒 AES Encryption Test~%")
    (format t "Plaintext: ~{~2,'0X~^ ~}~%" (coerce pt 'list))
    (format t "Key:       ~{~2,'0X~^ ~}~%" (coerce key 'list))
    (format t "Expected:  ~{~2,'0X~^ ~}~%" (coerce expected 'list))
    (format t "Output:    ~{~2,'0X~^ ~}~%" (coerce output 'list))
    (if (equalp output expected)
        (format t "✅ Match confirmed.~%")
        (progn
          (format t "❌ Mismatch detected.~%")
          (dotimes (i 16)
            (unless (equalp (aref output i) (aref expected i))
              (format t "Byte ~D mismatch: Expected ~2,'0X, got ~2,'0X~%"
                      i (aref expected i) (aref output i))))))))

;; To run the test:
;; (in-package :aes-test)
;; (run-test)
