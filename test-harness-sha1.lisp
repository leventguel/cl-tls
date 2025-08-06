(ql:quickload :ironclad)

(defun ironclad-sha1 (bytes)
  (ironclad:byte-array-to-hex-string
   (ironclad:digest-sequence :sha1 bytes)))

(load "/home/wbooze/clocc/src/ssl/sha1.lisp")

(defun my-sha (bytes)
  ;; Replace this with a call to your own sha1-hex function
  (sha1-hex bytes))

(defun string-to-bytes (str)
  (map 'vector #'char-code str))

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

(defun run-all-tests ()
  (run-test "Test 1: Empty string" #())
  (run-test "Test 2: 'abc'" #(97 98 99))
  (run-test "Test 3: 'The quick brown fox...'" (string-to-bytes "The quick brown fox jumps over the lazy dog"))
  (run-test "Test 4: 'The quick brown fox...' with period" (string-to-bytes "The quick brown fox jumps over the lazy dog."))
  (run-test "Test 5: 1 million 'a'" (make-array 1000000 :element-type '(unsigned-byte 8) :initial-element 97)))

(run-all-tests)
