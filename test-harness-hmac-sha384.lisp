;; test-harness-hmac-sha384.lisp

(ql:quickload :ironclad)

(load "~/clocc/src/ssl/hmac-sha384.lisp") ; Adjust path if needed

(defun ironclad-hmac-sha384 (key message)
  (let* ((block-size 128)
         (key (if (> (length key) block-size)
                  (ironclad:digest-sequence :sha384 key)
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
     (ironclad:digest-sequence :sha384
       (concatenate '(vector (unsigned-byte 8))
                    opad
                    (words64-vector-to-bytes (ironclad:digest-sequence :sha384
                      (concatenate '(vector (unsigned-byte 8)) ipad message))))))))

(defun my-hmac-sha384 (key message)
  (hmac-sha384-hex key message)) ; Your implementation

(defun string-to-bytes (str)
  (map 'vector #'char-code str))

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
  (run-test "Test 1: key = 0x0b * 20, msg = 'Hi There'"
            (make-array 20 :element-type '(unsigned-byte 8) :initial-element #x0b)
            (string-to-bytes "Hi There"))

  ;; RFC 4231 Test Case 2
  (run-test "Test 2: key = 'Jefe', msg = 'what do ya want for nothing?'"
            (string-to-bytes "Jefe")
            (string-to-bytes "what do ya want for nothing?"))

  ;; RFC 4231 Test Case 3
  (run-test "Test 3: key = 0xaa * 20, msg = 0xdd * 50"
            (make-array 20 :element-type '(unsigned-byte 8) :initial-element #xaa)
            (make-array 50 :element-type '(unsigned-byte 8) :initial-element #xdd)))

(run-all-tests)
