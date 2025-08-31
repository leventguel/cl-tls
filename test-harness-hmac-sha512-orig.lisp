(in-package :hmac-sha512)

(ql:quickload :ironclad)

(load "~/clocc/src/ssl/sha-utils.lisp")
(load "~/clocc/src/ssl/hmac-sha512.lisp") ; Adjust path if needed

(defun ironclad-hmac-sha512 (key message)
  (let* ((block-size 128)
         (key (if (> (length key) block-size)
                  (ironclad:digest-sequence :sha512 key)
                  key))
         (key (concatenate '(vector (unsigned-byte 8))
                           key
                           (make-array (- block-size (length key))
                                       :element-type '(unsigned-byte 8)
                                       :initial-element 0)))
         (ipad (make-array block-size :element-type '(unsigned-byte 8)
                                      :initial-element #x36))
         (opad (make-array block-size :element-type '(unsigned-byte 8)
                                      :initial-element #x5c)))
    (loop for i from 0 below block-size do
      (setf (aref ipad i) (logxor (aref ipad i) (aref key i))
            (aref opad i) (logxor (aref opad i) (aref key i))))
    (ironclad:byte-array-to-hex-string
     (ironclad:digest-sequence :sha512
       (concatenate '(vector (unsigned-byte 8))
                    opad
                    (ironclad:digest-sequence :sha512
                      (concatenate '(vector (unsigned-byte 8)) ipad message)))))))

(defun my-sha512 (bytes)
  (hmac-sha512-hex key message)) ; Your implementation

(defun string-to-bytes (str)
  (map 'vector #'char-code str))

(defun run-test (label input)
  (let* ((bytes (make-array (length input)
                            :element-type '(unsigned-byte 8)
                            :initial-contents input))
         (expected (string-downcase (ironclad-hmac-sha512 bytes)))
         (actual   (string-downcase (my-sha512 bytes))))
    (format t "~%~A~%Input: ~S~%Expected: ~A~%Actual:   ~A~%"
            label input expected actual)
    (if (string= expected actual)
        (format t "✅ PASS~%")
        (format t "❌ FAIL~%"))))

(defun run-all-tests ()
  ;; RFC 6234 Test 1: Empty string
  (run-test "Test 1: Empty string" #())

  ;; RFC 6234 Test 2: "abc"
  (run-test "Test 2: 'abc'" (string-to-bytes "abc"))

  ;; RFC 6234 Test 3: "The quick brown fox jumps over the lazy dog"
  (run-test "Test 3: Quick brown fox" (string-to-bytes "The quick brown fox jumps over the lazy dog"))

  ;; RFC 6234 Test 4: Same with period
  (run-test "Test 4: Quick brown fox with period" (string-to-bytes "The quick brown fox jumps over the lazy dog."))

  ;; RFC 6234 Test 5: 1 million 'a'
  (run-test "Test 5: 1 million 'a'" (make-array 1000000 :element-type '(unsigned-byte 8) :initial-element 97)))

(run-all-tests)
