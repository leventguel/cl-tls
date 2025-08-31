(in-package :sha512)
;; test-harness-hmac-sha512.lisp

(load "~/clocc/src/ssl/sha-utils.lisp")
(load "~/clocc/src/ssl/sha512.lisp") ; Adjust path if needed

(defun ironclad-sha512 (bytes)
  (ironclad:byte-array-to-hex-string
   (ironclad:digest-sequence :sha512 bytes)))

(defun my-sha512 (bytes)
  (sha512-hex bytes)) ; Your implementation

(defun run-test (label input)
  (let* ((bytes (make-array (length input)
                            :element-type '(unsigned-byte 8)
                            :initial-contents input))
         (expected (string-downcase (ironclad-sha512 bytes)))
         (actual   (string-downcase (my-sha512 bytes))))
    (format t "~%~A~%Input: ~S~%Expected: ~A~%Actual:   ~A~%"
            label input expected actual)
    (if (string= expected actual)
        (format t "✅ PASS~%")
        (format t "❌ FAIL~%"))))

(defun test-one-million-sha512 ()
  ;; RFC 6234 Test 5: 1 million 'a'
  (run-test "Test 5: 1 million 'a'" (make-array 1000000 :element-type '(unsigned-byte 8) :initial-element 97)))

(defun run-all-tests ()
  ;; RFC 6234 Test 1: Empty string
  (run-test "Test 1: Empty string" #())
  ;; RFC 6234 Test 2: "abc"
  (run-test "Test 2: 'abc'" (string-to-bytes "abc"))
  ;; RFC 6234 Test 3: "The quick brown fox jumps over the lazy dog"
  (run-test "Test 3: Quick brown fox" (string-to-bytes "The quick brown fox jumps over the lazy dog"))
  ;; RFC 6234 Test 4: Same with period
  (run-test "Test 4: Quick brown fox with period" (string-to-bytes "The quick brown fox jumps over the lazy dog.")))
  
(run-all-tests)
