(in-package :tls-aes192)

(defun print-round-keys (expanded-key)
  "Prints all 11 round keys from the given expanded AES key."
  (format t "~%🔑 Round Keys Dump~%")
  (dotimes (i 11)
    (format t "Round ~D: " i)
    (loop for byte across (round-key expanded-key i)
          do (format t "~2,'0X" byte))  ; ← this was missing `byte`
    (terpri)))

(defun trace-aes-block (pt expanded-key)
  "Prints each transformation stage for one AES-192 ECB block encryption."
  (let ((state (copy-seq pt)))
    (format t "~%🔓 Plaintext: ~{~2,'0X~^ ~}~%" (coerce state 'list))
    (format t "🔑 KeyAddition (Round 0): ")
    (setf state (add-round-key state (round-key expanded-key 0)))
    (format t "~{~2,'0X~^ ~}~%" (coerce state 'list))

    (dotimes (round 9)
      (format t "~%=== Round ~D ===~%" (1+ round))
      (setf state (sub-bytes-matrix state))
      (format t "🧬 SubBytes:   ~{~2,'0X~^ ~}~%" (coerce state 'list))

      (setf state (shift-rows state))
      (format t "🔄 ShiftRows:  ~{~2,'0X~^ ~}~%" (coerce state 'list))

      (setf state (mix-columns state))
      (format t "🔗 MixColumns: ~{~2,'0X~^ ~}~%" (coerce state 'list))

      (setf state (add-round-key state (round-key expanded-key (+ round 1))))
      (format t "🔐 AddRoundKey:~{~2,'0X~^ ~}~%" (coerce state 'list)))

    ;; Final Round (no MixColumns)
    (format t "~%=== Final Round ===~%")
    (setf state (sub-bytes-matrix state))
    (format t "🧬 SubBytes:   ~{~2,'0X~^ ~}~%" (coerce state 'list))

    (setf state (shift-rows state))
    (format t "🔄 ShiftRows:  ~{~2,'0X~^ ~}~%" (coerce state 'list))

    (setf state (add-round-key state (round-key expanded-key 10)))
    (format t "🔐 Final KeyAdd:~{~2,'0X~^ ~}~%" (coerce state 'list))

    (format t "~%🧱 Ciphertext: ~{~2,'0X~^ ~}~%" (coerce state 'list))
    state))  ; return final ciphertext

(defun trace-ecb-encryption (plaintext expanded-key)
  "Trace AES-192 ECB encryption stages for each 16-byte block in the plaintext."
  (loop for i from 0 below (length plaintext) by 16
        for block = (subseq plaintext i (+ i 16))
        for index = (/ i 16)
        do (format t "~%==================================================~%")
           (format t "🔢 Block ~D~%" index)
           (trace-aes-block block expanded-key)))

(defun trace-ecb-encrypt-all (plaintext expanded-key)
  "Encrypt all blocks and return the full ciphertext."
  (let ((ciphertext '()))
    (loop for i from 0 below (length plaintext) by 16
          for block = (subseq plaintext i (+ i 16))
          do (push (trace-aes-block block expanded-key) ciphertext))
    (let ((flat (apply #'concatenate 'vector (reverse ciphertext))))
      (format t "~%🧱 Full Final Ciphertext: ~{~2,'0X~^ ~}~%" (coerce flat 'list))
      flat)))

(defun run-test ()
  "Runs AES-192 test vector and prints match result."
  (let* ((key-str "2b7e151628aed2a6abf7158809cf4f3c")
         (pt-str  "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710")
         (ct-str  "3ad77bb40d7a3660a89ecaf32466ef97f5d3d58503b9699de785895a96fdbaaf43b1cd7f598ece23881b00e3ed0306887b0c785e27e8ad3f8223207104725dd4")
         (key     (hex-string-to-byte-vector key-str))
         (pt      (hex-string-to-byte-vector pt-str))
         (expected (hex-string-to-byte-vector ct-str))
         (output   (aes192-ecb-encrypt pt key)))
    (format t "~%🔒 AES Encryption Test~%")
    (format t "Plaintext: ~{~2,'0X~^ ~}~%" (coerce pt 'list))
    (format t "Key:       ~{~2,'0X~^ ~}~%" (coerce key 'list))
    (format t "Expected:  ~{~2,'0X~^ ~}~%" (coerce expected 'list))
    (format t "Output:    ~{~2,'0X~^ ~}~%" (coerce output 'list))
    (if (equalp output expected)
        (format t "✅ Match confirmed.~%")
        (progn
          (format t "❌ Mismatch detected.~%")
          (dotimes (i 16)
            (unless (equalp (aref output i) (aref expected i))
              (format t "Byte ~D mismatch: Expected ~2,'0X, got ~2,'0X~%"
                      i (aref expected i) (aref output i))))))))

(defparameter *test-key*
  (hex-string-to-byte-vector "2b7e151628aed2a6abf7158809cf4f3c"))

(defparameter *test-plaintext*
  (hex-string-to-byte-vector
   "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad\
b417be66c3710"))

;; Encrypt it
(defparameter *test-ciphertext*
  (aes192-ecb-encrypt *test-plaintext* *test-key*))

;; Decrypt it
(defparameter *recovered-plaintext*
  (aes192-ecb-decrypt *test-ciphertext* *test-key*))

(format t "~%✅ Test Passed: ~A~%"
        (equalp *recovered-plaintext* *test-plaintext*))

;; Padding test
(defparameter *short-plaintext*
  #(1 2 3 4 5 6 7 8 9 10)) ;; 10 bytes

(defparameter *padded*
  (pad-pkcs7 *short-plaintext* 16))

(format t "~%Padded: ~{~2,'0X~^ ~}~%" (coerce *padded* 'list))

(defparameter *key*
  (hex-string-to-byte-vector "2b7e151628aed2a6abf7158809cf4f3c"))

(defparameter *enc-block*
  (aes192-ecb-encrypt-block *padded* *key*))

(defparameter *expanded-key*
  (expand-key-192 (copy-seq *key*)))

(defparameter *dec-block*
  (aes192-ecb-decrypt-block *enc-block* *expanded-key*))

(format t "~%Decrypted Block: ~{~2,'0X~^ ~}~%" (coerce *dec-block* 'list))

(defparameter *unpadded*
  (maybe-unpad-pkcs7 *dec-block* 16))

(format t "~%Unpadded: ~{~2,'0X~^ ~}~%" (coerce *unpadded* 'list))
