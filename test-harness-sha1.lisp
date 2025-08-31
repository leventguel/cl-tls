(in-package :sha1)

(ql:quickload :ironclad)

(defun ironclad-sha1 (bytes)
  (ironclad:byte-array-to-hex-string
   (ironclad:digest-sequence :sha1 bytes)))

(load "~/clocc/src/ssl/sha-utils.lisp")
(load "~/clocc/src/ssl/sha1.lisp")

(defun my-sha (bytes)
  ;; Replace this with a call to your own sha1-hex function
  (sha1-hex bytes))

(defun run-test (label input)
  (let* ((bytes (make-array (length input)
                            :element-type '(unsigned-byte 8)
                            :initial-contents input))
         (expected (ironclad-sha1 bytes))
         (actual (my-sha bytes)))
    (format t "~%~A~%Input: ~S~%Expected: ~A~%Actual:   ~A~%"
            label input expected actual)
    (if (string= expected actual)
        (format t "✅ PASS~%")
        (format t "❌ FAIL~%"))))

(defun test-one-million-sha1 ()
  (run-test "SHA1 Test 5: 1 million 'a'" (make-array 1000000 :element-type '(unsigned-byte 8) :initial-element 97)))

(defun run-all-tests (&optional one-million)
  (run-test "SHA1 Test 1: Empty string" #())
  (run-test "SHA1 Test 2: 'abc'" #(97 98 99))
  (run-test "SHA1 Test 3: 'The quick brown fox...'"
	    (string-to-bytes "The quick brown fox jumps over the lazy dog"))
  (run-test "SHA1 Test 4: 'The quick brown fox...' with period"
	    (string-to-bytes "The quick brown fox jumps over the lazy dog."))
  (when one-million
    (test-one-million-sha1)))
