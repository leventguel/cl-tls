(in-package :hmac-sha384)
;; test-harness-hmac-sha384.lisp

(load "~/clocc/src/ssl/sha-utils.lisp")
(load "~/clocc/src/ssl/hmac-sha384.lisp") ; Adjust path if needed

(defun my-hmac-sha384 (key message)
  (hmac-sha384-hex key message)) ;; Your implementation

(defun run-test (label key message)
  (let* ((expected (string-downcase (ironclad-hmac-sha384 key message)))
         (actual   (string-downcase (my-hmac-sha384 key message))))
    (format t "~%~A~%Expected: ~A~%Actual:   ~A~%"
            label expected actual)
    (if (string= expected actual)
        (format t "✅ PASS~%")
        (format t "❌ FAIL~%"))))

(defun run-all-tests ()
  ;; RFC 4231 Test Case 1
  (run-test "HMAC-SHA384 Test 1: key = 0x0b * 20, msg = 'Hi There'"
            (make-array 20 :element-type '(unsigned-byte 8) :initial-element #x0b)
            (string-to-bytes "Hi There"))

  ;; RFC 4231 Test Case 2
  (run-test "HMAC-SHA384 Test 2: key = 'Jefe', msg = 'what do ya want for nothing?'"
            (string-to-bytes "Jefe")
            (string-to-bytes "what do ya want for nothing?"))

  ;; RFC 4231 Test Case 3
  (run-test "HMAC-SHA384 Test 3: key = 0xaa * 20, msg = 0xdd * 50"
            (make-array 20 :element-type '(unsigned-byte 8) :initial-element #xaa)
            (make-array 50 :element-type '(unsigned-byte 8) :initial-element #xdd)))
