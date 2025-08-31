(in-package :hmac-sha256)
;; test-harness-hmac-sha256.lisp

(load "~/clocc/src/ssl/sha-utils.lisp")
(load "~/clocc/src/ssl/hmac-sha256.lisp") ; Adjust path if needed

(defun my-hmac-sha256 (key message)
  (hmac-sha256-hex key message))

(defun run-test (label key message)
  (let* ((expected (string-downcase (ironclad-hmac-sha256 key message)))
         (actual   (string-downcase (my-hmac-sha256 key message))))
    (format t "~%~A~%Expected: ~A~%Actual:   ~A~%"
            label expected actual)
    (if (string= expected actual)
        (format t "✅ PASS~%")
        (format t "❌ FAIL~%"))))

(defun run-all-tests ()
  ;; RFC 4231 Test Case 1
  (run-test "Test 1: key = #x0b * 20, msg = 'Hi There'"
            (make-array 20 :element-type '(unsigned-byte 8) :initial-element #x0b)
            (string-to-bytes "Hi There"))

  ;; RFC 4231 Test Case 2
  (run-test "Test 2: key = 'Jefe', msg = 'what do ya want for nothing?'"
            (string-to-bytes "Jefe")
            (string-to-bytes "what do ya want for nothing?"))

  ;; RFC 4231 Test Case 3
  (run-test "Test 3: key = #xaa * 20, msg = #xdd * 50"
            (make-array 20 :element-type '(unsigned-byte 8) :initial-element #xaa)
            (make-array 50 :element-type '(unsigned-byte 8) :initial-element #xdd)))

(run-all-tests)
