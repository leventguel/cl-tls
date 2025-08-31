(in-package :sha256)

(ql:quickload :ironclad)

(defun ironclad-sha256 (bytes)
  (ironclad:byte-array-to-hex-string
   (ironclad:digest-sequence :sha256 bytes)))

(load "~/clocc/src/ssl/sha-utils.lisp")
(load "~/clocc/src/ssl/sha256.lisp")

(defun my-sha256 (bytes)
  ;; Replace this with a call to your own sha256-hex function
  (sha256-hex bytes))

(defun run-test (label input)
  (let* ((bytes (make-array (length input)
                            :element-type '(unsigned-byte 8)
                            :initial-contents input))
         (expected (ironclad-sha256 bytes))
         (actual (my-sha256 bytes)))
    (format t "~%~A~%Input: ~S~%Expected: ~A~%Actual:   ~A~%"
            label input expected actual)
    (if (string= expected actual)
        (format t "✅ PASS~%")
        (format t "❌ FAIL~%"))))

(defun test-one-million-sha256 ()
  (run-test "Test 5: 1 million 'a'" (make-array 1000000 :element-type '(unsigned-byte 8) :initial-element 97)))

(defun run-all-tests ()
  (run-test "Test 1: Empty string" #())
  (run-test "Test 2: 'abc'" #(97 98 99))
  (run-test "Test 3: 'The quick brown fox...'" (string-to-bytes "The quick brown fox jumps over the lazy dog"))
  (run-test "Test 4: 'The quick brown fox...' with period" (string-to-bytes "The quick brown fox jumps over the lazy dog.")))

(run-all-tests)

