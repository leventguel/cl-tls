(in-package :sha224)

(ql:quickload :ironclad)

(defun ironclad-sha224 (bytes)
  (ironclad:byte-array-to-hex-string
   (ironclad:digest-sequence :sha224 bytes)))

(load "~/clocc/src/ssl/sha-utils.lisp")
(load "~/clocc/src/ssl/sha224.lisp")

(defun my-sha224 (bytes)
  ;; Replace this with a call to your own sha256-hex function
  (sha224-hex bytes))

(defun run-test (label input)
  (let* ((bytes (make-array (length input)
                            :element-type '(unsigned-byte 8)
                            :initial-contents input))
         (expected (ironclad-sha224 bytes))
         (actual (my-sha224 bytes)))
    (format t "~%~A~%Input: ~S~%Expected: ~A~%Actual:   ~A~%"
            label input expected actual)
    (if (string= expected actual)
        (format t "✅ PASS~%")
        (format t "❌ FAIL~%"))))

(defun test-one-million-sha224 ()
  (run-test "SHA224 Test 5: 1 million 'a'" (make-array 1000000 :element-type '(unsigned-byte 8) :initial-element 97)))

(defun run-all-tests (&optional one-million)
  (run-test "SHA224 Test 1: Empty string" #())
  (run-test "SHA224 Test 2: 'abc'" #(97 98 99))
  (run-test "SHA224 Test 3: 'The quick brown fox...'"
	    (string-to-bytes "The quick brown fox jumps over the lazy dog"))
  (run-test "SHA224 Test 4: 'The quick brown fox...' with period"
	    (string-to-bytes "The quick brown fox jumps over the lazy dog."))
  (when one-million
    (test-one-million-sha224)))

