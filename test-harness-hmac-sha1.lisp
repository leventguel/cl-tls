(in-package :hmac-sha1)
;; test-harness-hmac-sha1.lisp

(load "~/clocc/src/ssl/sha-utils.lisp")
(load "~/clocc/src/ssl/hmac-sha1.lisp")

(defun my-hmac-sha1 (key message)
  (hmac-sha1-hex key message)) ; uses your own hmac-sha1

(defun run-test (label key input)
  (let* ((expected (string-downcase (ironclad-hmac-sha1 key input)))
         (actual   (string-downcase (my-hmac-sha1 key input))))
    (format t "~%~A~%Expected: ~A~%Actual:   ~A~%"
            label expected actual)
    (if (string= expected actual)
        (format t "✅ PASS~%")
        (format t "❌ FAIL~%"))))

(defun run-all-tests ()
  ;; RFC 2202 Test 1
  (run-test "HMAC-SHA1 Test 1: key = 0x0b * 20, msg = 'Hi There'"
            (make-array 20 :element-type '(unsigned-byte 8) :initial-element #x0b)
            (string-to-bytes "Hi There"))

  ;; RFC 2202 Test 2
  (run-test "HMAC-SHA1 Test 2: key = 'Jefe', msg = 'what do ya want for nothing?'"
            (string-to-bytes "Jefe")
            (string-to-bytes "what do ya want for nothing?"))

  ;; RFC 2202 Test 3
  (run-test "HMAC-SHA1 Test 3: key = 0xaa * 20, msg = 0xdd * 50"
            (make-array 20 :element-type '(unsigned-byte 8) :initial-element #xaa)
            (make-array 50 :element-type '(unsigned-byte 8) :initial-element #xdd)))
