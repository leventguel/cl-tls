(defpackage :double-des
  (:use :cl :shared-utils :des-utils :des-padding :des-base64 :des-constants :des-core :des-context :des-api)
  (:export :double-des-ecb-encrypt :double-des-ecb-decrypt
	   :double-des-cbc-encrypt :double-des-cbc-decrypt
	   :double-des-cfb-encrypt :double-des-cfb-decrypt
	   :double-des-cfb8-encrypt :double-des-cfb8-decrypt
	   :double-des-cfb1-encrypt :double-des-cfb1-decrypt
	   :double-des-ofb-encrypt :double-des-ofb-decrypt
	   :double-des-ctr-encrypt :double-des-ctr-decrypt
	   :double-des-ecb-encrypt-base64 :double-des-ecb-decrypt-base64
	   :double-des-cbc-encrypt-base64 :double-des-cbc-decrypt-base64
	   :double-des-cfb-encrypt-base64 :double-des-cfb-decrypt-base64
	   :double-des-cfb8-encrypt-base64 :double-des-cfb8-decrypt-base64
	   :double-des-cfb1-encrypt-base64 :double-des-cfb1-decrypt-base64
	   :double-des-ofb-encrypt-base64 :double-des-ofb-decrypt-base64
	   :double-des-ctr-encrypt-base64 :double-des-ctr-decrypt-base64
	   :double-des-ecb-encrypt-file :double-des-ecb-decrypt-file
	   :double-des-cbc-encrypt-file :double-des-cbc-decrypt-file
	   :double-des-cfb-encrypt-file :double-des-cfb-decrypt-file
	   :double-des-cfb8-encrypt-file :double-des-cfb8-decrypt-file
	   :double-des-cfb1-encrypt-file :double-des-cfb1-decrypt-file
	   :double-des-ofb-encrypt-file :double-des-ofb-decrypt-file
	   :double-des-ctr-encrypt-file :double-des-ctr-decrypt-file
	   :double-des-ecb-encrypt-file-base64 :double-des-ecb-decrypt-file-base64
	   :double-des-cbc-encrypt-file-base64 :double-des-cbc-decrypt-file-base64
	   :double-des-cfb-encrypt-file-base64 :double-des-cfb-decrypt-file-base64
	   :double-des-cfb8-encrypt-file-base64 :double-des-cfb8-decrypt-file-base64
	   :double-des-cfb1-encrypt-file-base64 :double-des-cfb1-decrypt-file-base64
	   :double-des-ofb-encrypt-file-base64 :double-des-ofb-decrypt-file-base64
	   :double-des-ctr-encrypt-file-base64 :double-des-ctr-decrypt-file-base64))

(in-package :double-des)

;; Variants
;; ECB mode encrypt
(defun double-des-ecb-encrypt (plaintext key1 key2)
  "Encrypt plaintext using Double DES in ECB (EDE) mode."
  (let* ((step1 (des-api::encrypt-string-ecb plaintext key1))
	 (step2 (des-api::decrypt-string-ecb step1 key2)))
    (des-api::encrypt-string-ecb step2 key1)))

;; ECB mode decrypt
(defun double-des-ecb-decrypt (ciphertext key1 key2)
  "Decrypt ciphertext using Double DES in ECB (EDE) mode."
  (let* ((step1 (des-api::decrypt-string-ecb ciphertext key1))
	 (step2 (des-api::encrypt-string-ecb step1 key2)))
    (des-api::decrypt-string-ecb step2 key1)))

;; CBC mode encrypt
(defun double-des-cbc-encrypt (plaintext key1 key2 iv)
  "Encrypt plaintext using Double DES in CBC mode with existing DES primitives."
  (let* ((padded (pad-byte-vector (string-to-byte-vector plaintext) 8))
	 (blocks (split-into-blocks padded 8))
         (previous-block (ensure-bit-vector iv))
         result)
    (dolist (block blocks)
      (let* ((block (ensure-bit-vector block))
             ;; CBC XOR step
	     (xored (map 'bit-vector #'logxor block previous-block))
	     ;; DES IV chainging has to be performed only once!
	     ;; we can't use des-api::des-cbc-encrypt-string since it always uses iv.
	     ;; and also it converts internal representations so we use ecb here again.
	     ;; Other modes are streaming not chaining like CBC, so no special handling required there.
	     
             ;; Double DES encryption: E_k3(D_k2(E_k1(xored)))
	     ;;(step1 (des-api::encrypt-string-ecb plaintext key1))
	     (step1 (des-ecb-encrypt-block xored (generate-round-keys (ensure-bit-vector key1) t)))
             ;;(step2 (des-api::decrypt-string-ecb step1 key2))
	     (step2 (des-ecb-decrypt-block step1 (generate-round-keys (ensure-bit-vector key2) t)))
	     ;;(cipher-block (des-api::encrypt-string-ecb step2 key1))
	     (cipher-block (des-ecb-encrypt-block step2 (generate-round-keys (ensure-bit-vector key1) t)))
	     )
        (push cipher-block result)
        (setf previous-block cipher-block)))
    ;; Convert bit-vectors to byte-vectors and flatten
    (apply #'concatenate 'vector
           (mapcar #'bit-vector-to-byte-vector (nreverse result)))))

;; CBC mode decrypt
(defun double-des-cbc-decrypt (ciphertext key1 key2 iv)
  "Decrypt ciphertext using Double DES in CBC mode with existing DES primitives."
  (let* ((blocks (split-into-blocks ciphertext 8))
         (previous-block (ensure-bit-vector iv))
         result)
    (dolist (block blocks)
      (let* ((block (ensure-bit-vector block))
	     ;; DES IV chainging has to be performed only once!
	     ;; we can't use des-api::des-cbc-decrypt-string since it always uses iv.
	     ;; and also it converts internal representations so we use ecb here again.
	     ;; Other modes are streaming not chaining like CBC, so no special handling required there.

             ;; Double DES decryption: D_k1(E_k2(D_k3(block)))
	     (step1 (des-ecb-decrypt-block block (generate-round-keys (ensure-bit-vector key1) t)))
	     ;;(step1 (des-api::decrypt-string-ecb ciphertext key1))
             (step2 (des-ecb-encrypt-block step1 (generate-round-keys (ensure-bit-vector key2) t)))
	     ;;(step2 (des-api::encrypt-string-ecb step1 key2))
	     (plaintext (des-ecb-decrypt-block step2 (generate-round-keys (ensure-bit-vector key1) t)))
	     ;;(plaintext (des-api::decrypt-string-ecb step2 key1))
             ;; CBC XOR step
	     (xored (map 'bit-vector #'logxor plaintext previous-block)))
        (push xored result)
        (setf previous-block block)))
    ;; Convert bit-vectors to byte-vectors and unpad
    (unpad-byte-vector
     (apply #'concatenate 'vector
            (mapcar #'bit-vector-to-byte-vector (nreverse result))))))

;; CFB mode encrypt
(defun double-des-cfb-encrypt (plaintext key1 key2 iv)
  "Encrypt plaintext using Double DES in CFB (EDE) mode with IV."
  (let* ((step1 (des-api::encrypt-string-cfb plaintext key1 iv))
	 (step2 (des-api::decrypt-string-cfb step1 key2 iv)))
    (des-api::encrypt-string-cfb step2 key1 iv)))

;; CFB mode decrypt
(defun double-des-cfb-decrypt (ciphertext key1 key2 iv)
  "Decrypt ciphertext using Double DES in CFB (EDE) mode with IV."
  (let* ((step1 (des-api::decrypt-string-cfb ciphertext key1 iv))
	 (step2 (des-api::encrypt-string-cfb step1 key2 iv)))
    (des-api::decrypt-string-cfb step2 key1 iv)))

;; CFB8 mode encrypt
(defun double-des-cfb8-encrypt (plaintext key1 key2 iv)
  "Encrypt plaintext using Double DES in CFB8 (EDE) mode with IV."
  (let* ((step1 (des-api::encrypt-string-cfb8 plaintext key1 iv))
	 (step2 (des-api::decrypt-string-cfb8 step1 key2 iv)))
    (des-api::encrypt-string-cfb8 step2 key1 iv)))

;; CFB8 mode decrypt
(defun double-des-cfb8-decrypt (ciphertext key1 key2 iv)
  "Decrypt ciphertext using Double DES in CFB8 (EDE) mode with IV."
  (let* ((step1 (des-api::decrypt-string-cfb8 ciphertext key1 iv))
	 (step2 (des-api::encrypt-string-cfb8 step1 key2 iv)))
    (des-api::decrypt-string-cfb8 step2 key1 iv)))

;; CFB1 mode encrypt
(defun double-des-cfb1-encrypt (plaintext key1 key2 iv)
  "Encrypt plaintext using Double DES in CFB1 (EDE) mode with IV."
  (let* ((step1 (des-api::encrypt-string-cfb1 plaintext key1 iv))
	 (step2 (des-api::decrypt-string-cfb1 step1 key2 iv)))
    (des-api::encrypt-string-cfb1 step2 key1 iv)))

;; CFB1 mode decrypt
(defun double-des-cfb1-decrypt (ciphertext key1 key2 iv)
  "Decrypt ciphertext using Double DES in CFB1 (EDE) mode with IV."
  (let* ((step1 (des-api::decrypt-string-cfb1 ciphertext key1 iv))
	 (step2 (des-api::encrypt-string-cfb1 step1 key2 iv)))
    (des-api::decrypt-string-cfb1 step2 key1 iv)))

;; OFB mode encrypt
(defun double-des-ofb-encrypt (plaintext key1 key2 iv)
  "Encrypt plaintext using Double DES in OFB (EDE) mode with IV."
  (let* ((step1 (des-api::encrypt-string-ofb plaintext key1 iv))
	 (step2 (des-api::decrypt-string-ofb step1 key2 iv)))
    (des-api::encrypt-string-ofb step2 key1 iv)))

;; OFB mode decrypt
(defun double-des-ofb-decrypt (ciphertext key1 key2 iv)
  "Decrypt ciphertext using Double DES in OFB (EDE) mode with IV."
  (let* ((step1 (des-api::decrypt-string-ofb ciphertext key1 iv))
	 (step2 (des-api::encrypt-string-ofb step1 key2 iv)))
    (des-api::decrypt-string-ofb step2 key1 iv)))

;; CTR mode encrypt
(defun double-des-ctr-encrypt (plaintext key1 key2 iv)
  "Encrypt plaintext using Double DES in CTR (EDE) mode with IV."
  (let* ((step1 (des-api::encrypt-string-ctr plaintext key1 iv))
	 (step2 (des-api::decrypt-string-ctr step1 key2 iv)))
    (des-api::encrypt-string-ctr step2 key1 iv)))

;; CTR mode decrypt
(defun double-des-ctr-decrypt (ciphertext key1 key2 iv)
  "Decrypt ciphertext using Double DES in CTR (EDE) mode with IV."
  (let* ((step1 (des-api::decrypt-string-ctr ciphertext key1 iv))
	 (step2 (des-api::encrypt-string-ctr step1 key2 iv)))
    (des-api::decrypt-string-ctr step2 key1 iv)))

;; Base64
;; ECB Base64 mode encrypt
(defun double-des-ecb-encrypt-base64 (plaintext key1 key2)
  "Base64 Encrypt plaintext using Double DES in ECB (EDE) mode."
  (des-base64:string-to-base64
   (double-des:double-des-ecb-encrypt plaintext key1 key2)))

;; ECB Base64 mode decrypt
(defun double-des-ecb-decrypt-base64 (b64 key1 key2)
  "Base64 Decrypt ciphertext using Double DES in ECB (EDE) mode."
  (double-des:double-des-ecb-decrypt
   (des-base64:base64-to-string b64) key1 key2))

;; CBC Base64 mode encrypt
(defun double-des-cbc-encrypt-base64 (plaintext key1 key2 iv)
  "Base64 Encrypt plaintext using Double DES in CBC (EDE) mode with IV."
  (des-base64:string-to-base64
   (double-des:double-des-cbc-encrypt plaintext key1 key2 iv)))

;; CBC Base64 mode decrypt
(defun double-des-cbc-decrypt-base64 (b64 key1 key2 iv)
  "Base64 Decrypt plaintext using Double DES in CBC (EDE) mode with IV."
  (double-des:double-des-cbc-decrypt
   (des-base64:base64-to-string b64) key1 key2 iv))

;; CFB Base64 mode encrypt
(defun double-des-cfb-encrypt-base64 (plaintext key1 key2 iv)
  "Base64 Encrypt plaintext using Double DES in CFB (EDE) mode with IV."
  (des-base64:string-to-base64
   (double-des:double-des-cfb-encrypt plaintext key1 key2 iv)))

;; CFB Base64 mode decrypt
(defun double-des-cfb-decrypt-base64 (b64 key1 key2 iv)
  "Base64 Decrypt plaintext using Double DES in CFB (EDE) mode with IV."
  (double-des:double-des-cfb-decrypt
   (des-base64:base64-to-string b64) key1 key2 iv))

;; CFB8 Base64 mode encrypt
(defun double-des-cfb8-encrypt-base64 (plaintext key1 key2 iv)
  "Base64 Encrypt plaintext using Double DES in CFB8 (EDE) mode with IV."
  (des-base64:string-to-base64
   (double-des:double-des-cfb8-encrypt plaintext key1 key2 iv)))

;; CFB8 Base64 mode decrypt
(defun double-des-cfb8-decrypt-base64 (b64 key1 key2 iv)
  "Base64 Decrypt plaintext using Double DES in CFB8 (EDE) mode with IV."
  (double-des:double-des-cfb8-decrypt
   (des-base64:base64-to-string b64) key1 key2 iv))

;; CFB1 Base64 mode encrypt
(defun double-des-cfb1-encrypt-base64 (plaintext key1 key2 iv)
  "Base64 Encrypt plaintext using Double DES in CFB1 (EDE) mode with IV."
  (des-base64:string-to-base64
   (double-des:double-des-cfb1-encrypt plaintext key1 key2 iv)))

;; CFB1 Base64 mode decrypt
(defun double-des-cfb1-decrypt-base64 (b64 key1 key2 iv)
  "Base64 Decrypt plaintext using Double DES in CFB1 (EDE) mode with IV."
  (double-des:double-des-cfb1-decrypt
   (des-base64:base64-to-string b64) key1 key2 iv))

;; OFB Base64 mode encrypt
(defun double-des-ofb-encrypt-base64 (plaintext key1 key2 iv)
  "Base64 Encrypt plaintext using Double DES in OFB (EDE) mode with IV."
  (des-base64:string-to-base64
   (double-des:double-des-ofb-encrypt plaintext key1 key2 iv)))

;; OFB Base64 mode decrypt
(defun double-des-ofb-decrypt-base64 (b64 key1 key2 iv)
  "Base64 Decrypt plaintext using Double DES in OFB (EDE) mode with IV."
  (double-des:double-des-ofb-decrypt
   (des-base64:base64-to-string b64) key1 key2 iv))

;; CTR Base64 mode encrypt
(defun double-des-ctr-encrypt-base64 (plaintext key1 key2 iv)
  "Base64 Encrypt plaintext using Double DES in CTR (EDE) mode with IV."
  (des-base64:string-to-base64
   (double-des:double-des-ctr-encrypt plaintext key1 key2 iv)))

;; CTR Base64 mode decrypt
(defun double-des-ctr-decrypt-base64 (b64 key1 key2 iv)
  "Base64 Decrypt plaintext using Double DES in CTR (EDE) mode with IV."
  (double-des:double-des-ctr-decrypt
   (des-base64:base64-to-string b64) key1 key2 iv))

;; File variants
;; ECB File mode encrypt
(defun double-des-ecb-encrypt-file (input-path output-path key1 key2)
  "Encrypt file using Double DES in ECB (EDE) mode."
  (let ((plaintext (des-utils:read-file-as-string input-path)))
    (des-utils:write-string-to-file
     output-path
     (double-des:double-des-ecb-encrypt plaintext key1 key2))))

;; ECB file mode decrypt
(defun double-des-ecb-decrypt-file (input-path output-path key1 key2)
  "Decrypt file using Double DES in ECB (EDE) mode."
  (let ((ciphertext (des-utils:read-file-as-string input-path)))
    (des-utils:write-string-to-file
     output-path
     (double-des:double-des-ecb-decrypt ciphertext key1 key2))))

;; CBC File mode encrypt
(defun double-des-cbc-encrypt-file (input-path output-path key1 key2 iv)
  "Encrypt file using Double DES in CBC (EDE) mode wiht IV."
  (let ((plaintext (des-utils:read-file-as-string input-path)))
    (des-utils:write-string-to-file
     output-path
     (double-des:double-des-cbc-encrypt plaintext key1 key2 iv))))

;; CBC file mode decrypt
(defun double-des-cbc-decrypt-file (input-path output-path key1 key2 iv)
  "Decrypt file using Double DES in CBC (EDE) mode wiht IV."
  (let ((ciphertext (des-utils:read-file-as-string input-path)))
    (des-utils:write-string-to-file
     output-path
     (double-des:double-des-cbc-decrypt ciphertext key1 key2 iv))))

;; CFB File mode encrypt
(defun double-des-cfb-encrypt-file (input-path output-path key1 key2 iv)
  "Encrypt file using Double DES in CFB (EDE) mode wiht IV."
  (let ((plaintext (des-utils:read-file-as-string input-path)))
    (des-utils:write-string-to-file
     output-path
     (double-des:double-des-cfb-encrypt plaintext key1 key2 iv))))

;; CFB file mode decrypt
(defun double-des-cfb-decrypt-file (input-path output-path key1 key2 iv)
  "Decrypt file using Double DES in CFB (EDE) mode wiht IV."
  (let ((ciphertext (des-utils:read-file-as-string input-path)))
    (des-utils:write-string-to-file
     output-path
     (double-des:double-des-cfb-decrypt ciphertext key1 key2 iv))))

;; CFB8 File mode encrypt
(defun double-des-cfb8-encrypt-file (input-path output-path key1 key2 iv)
  "Encrypt file using Double DES in CFB8 (EDE) mode wiht IV."
  (let ((plaintext (des-utils:read-file-as-string input-path)))
    (des-utils:write-string-to-file
     output-path
     (double-des:double-des-cfb8-encrypt plaintext key1 key2 iv))))

;; CFB8 file mode decrypt
(defun double-des-cfb8-decrypt-file (input-path output-path key1 key2 iv)
  "Decrypt file using Double DES in CFB8 (EDE) mode wiht IV."
  (let ((ciphertext (des-utils:read-file-as-string input-path)))
    (des-utils:write-string-to-file
     output-path
     (double-des:double-des-cfb8-decrypt ciphertext key1 key2 iv))))

;; CFB1 File mode encrypt
(defun double-des-cfb1-encrypt-file (input-path output-path key1 key2 iv)
  "Encrypt file using Double DES in CFB1 (EDE) mode wiht IV."
  (let ((plaintext (des-utils:read-file-as-string input-path)))
    (des-utils:write-string-to-file
     output-path
     (double-des:double-des-cfb1-encrypt plaintext key1 key2 iv))))

;; CFB1 file mode decrypt
(defun double-des-cfb1-decrypt-file (input-path output-path key1 key2 iv)
  "Decrypt file using Double DES in CFB1 (EDE) mode wiht IV."
  (let ((ciphertext (des-utils:read-file-as-string input-path)))
    (des-utils:write-string-to-file
     output-path
     (double-des:double-des-cfb1-decrypt ciphertext key1 key2 iv))))

;; OFB File mode encrypt
(defun double-des-ofb-encrypt-file (input-path output-path key1 key2 iv)
  "Encrypt file using Double DES in OFB (EDE) mode wiht IV."
  (let ((plaintext (des-utils:read-file-as-string input-path)))
    (des-utils:write-string-to-file
     output-path
     (double-des:double-des-ofb-encrypt plaintext key1 key2 iv))))

;; OFB file mode decrypt
(defun double-des-ofb-decrypt-file (input-path output-path key1 key2 iv)
  "Decrypt file using Double DES in OFB (EDE) mode wiht IV."
  (let ((ciphertext (des-utils:read-file-as-string input-path)))
    (des-utils:write-string-to-file
     output-path
     (double-des:double-des-ofb-decrypt ciphertext key1 key2 iv))))

;; CTR File mode encrypt
(defun double-des-ctr-encrypt-file (input-path output-path key1 key2 iv)
  "Encrypt file using Double DES in CTR (EDE) mode wiht IV."
  (let ((plaintext (des-utils:read-file-as-string input-path)))
    (des-utils:write-string-to-file
     output-path
     (double-des:double-des-ctr-encrypt plaintext key1 key2 iv))))

;; CTR file mode decrypt
(defun double-des-ctr-decrypt-file (input-path output-path key1 key2 iv)
  "Decrypt file using Double DES in CTR (EDE) mode wiht IV."
  (let ((ciphertext (des-utils:read-file-as-string input-path)))
    (des-utils:write-string-to-file
     output-path
     (double-des:double-des-ctr-decrypt ciphertext key1 key2 iv))))

;; Base64 File variants
;; ECB Base64 File mode encrypt
(defun double-des-ecb-encrypt-file-base64 (input-path output-path key1 key2)
  "Base64 Encrypt file using Double DES in ECB (EDE) mode."
  (let ((plaintext (des-utils:read-file-as-string input-path)))
    (des-utils:write-string-to-file
     output-path
     (double-des:double-des-ecb-encrypt-base64 plaintext key1 key2))))

;; ECB Base64 File mode decrypt
(defun double-des-ecb-decrypt-file-base64 (input-path output-path key1 key2)
  "Base64 Decrypt file using Double DES in ECB (EDE) mode."
  (let ((ciphertext (des-utils:read-file-as-string input-path)))
    (des-utils:write-string-to-file
     output-path
     (double-des:double-des-ecb-decrypt-base64 ciphertext key1 key2))))

;; CBC Base64 File mode encrypt
(defun double-des-cbc-encrypt-file-base64 (input-path output-path key1 key2 iv)
  "Base64 Encrypt file using Double DES in CBC (EDE) mode with IV."
  (let ((plaintext (des-utils:read-file-as-string input-path)))
    (des-utils:write-string-to-file
     output-path
     (double-des:double-des-cbc-encrypt-base64 plaintext key1 key2 iv))))

;; CBC Base64 File mode decrypt
(defun double-des-cbc-decrypt-file-base64 (input-path output-path key1 key2 iv)
  "Base64 Decrypt file using Double DES in CBC (EDE) mode with IV."
  (let ((ciphertext (des-utils:read-file-as-string input-path)))
    (des-utils:write-string-to-file
     output-path
     (double-des:double-des-cbc-decrypt-base64 ciphertext key1 key2 iv))))

;; CFB Base64 File mode encrypt
(defun double-des-cfb-encrypt-file-base64 (input-path output-path key1 key2 iv)
  "Base64 Encrypt file using Double DES in CFB (EDE) mode with IV."
  (let ((plaintext (des-utils:read-file-as-string input-path)))
    (des-utils:write-string-to-file
     output-path
     (double-des:double-des-cfb-encrypt-base64 plaintext key1 key2 iv))))

;; CFB Base64 File mode decrypt
(defun double-des-cfb-decrypt-file-base64 (input-path output-path key1 key2 iv)
  "Base64 Decrypt file using Double DES in CFB (EDE) mode with IV."
  (let ((ciphertext (des-utils:read-file-as-string input-path)))
    (des-utils:write-string-to-file
     output-path
     (double-des:double-des-cfb-decrypt-base64 ciphertext key1 key2 iv))))

;; CFB8 Base64 File mode encrypt
(defun double-des-cfb8-encrypt-file-base64 (input-path output-path key1 key2 iv)
  "Base64 Encrypt file using Double DES in CFB8 (EDE) mode with IV."
  (let ((plaintext (des-utils:read-file-as-string input-path)))
    (des-utils:write-string-to-file
     output-path
     (double-des:double-des-cfb8-encrypt-base64 plaintext key1 key2 iv))))

;; CFB8 Base64 File mode decrypt
(defun double-des-cfb8-decrypt-file-base64 (input-path output-path key1 key2 iv)
  "Base64 Decrypt file using Double DES in CFB8 (EDE) mode with IV."
  (let ((ciphertext (des-utils:read-file-as-string input-path)))
    (des-utils:write-string-to-file
     output-path
     (double-des:double-des-cfb8-decrypt-base64 ciphertext key1 key2 iv))))

;; CFB1 Base64 File mode encrypt
(defun double-des-cfb1-encrypt-file-base64  (input-path output-path key1 key2 iv)
  "Base64 Encrypt file using Double DES in CFB1 (EDE) mode with IV."
  (let ((plaintext (des-utils:read-file-as-string input-path)))
    (des-utils:write-string-to-file
     output-path
     (double-des:double-des-cfb1-encrypt-base64 plaintext key1 key2 iv))))

;; CFB1 Base64 File mode decrypt
(defun double-des-cfb1-decrypt-file-base64 (input-path output-path key1 key2 iv)
  "Base64 Decrypt file using Double DES in CFB1 (EDE) mode with IV."
  (let ((ciphertext (des-utils:read-file-as-string input-path)))
    (des-utils:write-string-to-file
     output-path
     (double-des:double-des-cfb1-decrypt-base64 ciphertext key1 key2 iv))))

;; OFB Base64 File mode encrypt
(defun double-des-ofb-encrypt-file-base64 (input-path output-path key1 key2 iv)
  "Base64 Encrypt file using Double DES in OFB (EDE) mode with IV."
  (let ((plaintext (des-utils:read-file-as-string input-path)))
    (des-utils:write-string-to-file
     output-path
     (double-des:double-des-ofb-encrypt-base64 plaintext key1 key2 iv))))

;; OFB Base64 File mode decrypt
(defun double-des-ofb-decrypt-file-base64 (input-path output-path key1 key2 iv)
  "Base64 Decrypt file using Double DES in OFB (EDE) mode with IV."
  (let ((ciphertext (des-utils:read-file-as-string input-path)))
    (des-utils:write-string-to-file
     output-path
     (double-des:double-des-ofb-decrypt-base64 ciphertext key1 key2 iv))))

;; CTR Base64 File mode encrypt
(defun double-des-ctr-encrypt-file-base64 (input-path output-path key1 key2 iv)
  "Base64 Encrypt file using Double DES in CTR (EDE) mode with IV."
  (let ((plaintext (des-utils:read-file-as-string input-path)))
    (des-utils:write-string-to-file
     output-path
     (double-des:double-des-ctr-encrypt-base64 plaintext key1 key2 iv))))

;; CTR Base64 File mode decrypt
(defun double-des-ctr-decrypt-file-base64 (input-path output-path key1 key2 iv)
  "Base64 Decrypt file using Double DES in CTR (EDE) mode with IV."
  (let ((ciphertext (des-utils:read-file-as-string input-path)))
    (des-utils:write-string-to-file
     output-path
     (double-des:double-des-ctr-decrypt-base64 ciphertext key1 key2 iv))))
