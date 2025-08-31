;; test-harness-tls-prf-sha384.lisp

(load "~/clocc/src/ssl/tls-prf-sha384.lisp")
(load "~/clocc/src/ssl/hmac-sha384.lisp")
(load "~/clocc/src/ssl/sha384.lisp")

(defun bytes-to-hex (byte-array)
  (string-downcase
   (with-output-to-string (s)
     (loop for b across byte-array
           do (format s "~2,'0X" b)))))

(defun string-to-array (str)
  (make-array (length str)
              :element-type '(unsigned-byte 8)
              :initial-contents (map 'list #'char-code str)))

(defun run-test (label secret label-str seed-str output-len expected-hex)
  (let* ((label-bytes (string-to-array label-str))
         (seed-bytes  (string-to-array seed-str))
         (actual-bytes (tls-prf-sha384 secret label-bytes seed-bytes output-len))
         (actual-hex   (bytes-to-hex actual-bytes)))
    (format t "~%~A~%Expected: ~A~%Actual:   ~A~%"
            label expected-hex actual-hex)
    (if (string= expected-hex actual-hex)
        (format t "✅ PASS~%")
        (format t "❌ FAIL~%"))))

(defun run-all-tests ()
  ;; Verified from OpenSSL EVP_KDF output
  (let ((secret (make-array 48 :element-type '(unsigned-byte 8)
                            :initial-element #x0b))
        (label "test label")
        (seed  "test seed")
        (output-len 64)
        (expected-hex "cc3a20273a70786a85656d30c0ad0c7be20bfd51d5d15c438225d8fb6a9482f13db0f0a0f541fbd7e6a761a8cd1974931dc4701d1d61c6b1910352ee06e26503"))
    (run-test "TLS PRF SHA384 — OpenSSL Verified" secret label seed output-len expected-hex)))

(run-all-tests)
