(ql:quickload :ironclad)

(defun ironclad-hmac-sha1 (key message)
  (let* ((block-size 64)
         (key (if (> (length key) block-size)
                  (ironclad:digest-sequence :sha1 key)
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
    ;; XOR key with ipad and opad
    (loop for i from 0 below block-size do
      (setf (aref ipad i) (logxor (aref ipad i) (aref key i))
            (aref opad i) (logxor (aref opad i) (aref key i))))
    ;; Inner hash
    (let ((inner (ironclad:digest-sequence :sha1
                  (concatenate '(vector (unsigned-byte 8)) ipad message))))
      ;; Outer hash
      (ironclad:byte-array-to-hex-string
       (ironclad:digest-sequence :sha1
         (concatenate '(vector (unsigned-byte 8)) opad inner))))))

(load "/home/wbooze/clocc/src/ssl/hmac-sha1.lisp")

(defun my-sha (key message)
  (bytes-to-hex (hmac-sha1 key message))) ; uses your own hmac-sha1

(defun string-to-bytes (str)
  (map 'vector #'char-code str))

(defun run-test (label key input)
  (let* ((expected (string-downcase (ironclad-hmac-sha1 key input)))
         (actual   (string-downcase (my-sha key input))))
    (format t "~%~A~%Expected: ~A~%Actual:   ~A~%"
            label expected actual)
    (if (string= expected actual)
        (format t "✅ PASS~%")
        (format t "❌ FAIL~%"))))

(defun run-all-tests ()
  ;; RFC 2202 Test 1
  (run-test "Test 1: key = 0x0b * 20, msg = 'Hi There'"
            (make-array 20 :element-type '(unsigned-byte 8) :initial-element #x0b)
            (string-to-bytes "Hi There"))

  ;; RFC 2202 Test 2
  (run-test "Test 2: key = 'Jefe', msg = 'what do ya want for nothing?'"
            (string-to-bytes "Jefe")
            (string-to-bytes "what do ya want for nothing?"))

  ;; RFC 2202 Test 3
  (run-test "Test 3: key = 0xaa * 20, msg = 0xdd * 50"
            (make-array 20 :element-type '(unsigned-byte 8) :initial-element #xaa)
            (make-array 50 :element-type '(unsigned-byte 8) :initial-element #xdd)))

(run-all-tests)
