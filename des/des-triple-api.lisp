(defpackage :triple-des
  (:use :cl :shared-utils :des-utils :des-padding :des-base64 :des-constants :des-core :des-context :des-api)
  (:export :triple-des-ecb-encrypt :triple-des-ecb-decrypt
	   :triple-des-cbc-encrypt :triple-des-cbc-decrypt
	   :triple-des-cfb-encrypt :triple-des-cfb-decrypt
	   :triple-des-cfb8-encrypt :triple-des-cfb8-decrypt
	   :triple-des-cfb1-encrypt :triple-des-cfb1-decrypt
	   :triple-des-ofb-encrypt :triple-des-ofb-decrypt
	   :triple-des-ctr-encrypt :triple-des-ctr-decrypt
	   :triple-des-ecb-encrypt-base64 :triple-des-ecb-decrypt-base64
	   :triple-des-cbc-encrypt-base64 :triple-des-cbc-decrypt-base64
	   :triple-des-cfb-encrypt-base64 :triple-des-cfb-decrypt-base64
	   :triple-des-cfb8-encrypt-base64 :triple-des-cfb8-decrypt-base64
	   :triple-des-cfb1-encrypt-base64 :triple-des-cfb1-decrypt-base64
	   :triple-des-ofb-encrypt-base64 :triple-des-ofb-decrypt-base64
	   :triple-des-ctr-encrypt-base64 :triple-des-ctr-decrypt-base64
	   :triple-des-ecb-encrypt-file :triple-des-ecb-decrypt-file
	   :triple-des-cbc-encrypt-file :triple-des-cbc-decrypt-file
	   :triple-des-cfb-encrypt-file :triple-des-cfb-decrypt-file
	   :triple-des-cfb8-encrypt-file :triple-des-cfb8-decrypt-file
	   :triple-des-cfb1-encrypt-file :triple-des-cfb1-decrypt-file
	   :triple-des-ofb-encrypt-file :triple-des-ofb-decrypt-file
	   :triple-des-ctr-encrypt-file :triple-des-ctr-decrypt-file
	   :triple-des-ecb-encrypt-file-base64 :triple-des-ecb-decrypt-file-base64
	   :triple-des-cbc-encrypt-file-base64 :triple-des-cbc-decrypt-file-base64
	   :triple-des-cfb-encrypt-file-base64 :triple-des-cfb-decrypt-file-base64
	   :triple-des-cfb8-encrypt-file-base64 :triple-des-cfb8-decrypt-file-base64
	   :triple-des-cfb1-encrypt-file-base64 :triple-des-cfb1-decrypt-file-base64
	   :triple-des-ofb-encrypt-file-base64 :triple-des-ofb-decrypt-file-base64
	   :triple-des-ctr-encrypt-file-base64 :triple-des-ctr-decrypt-file-base64))

(in-package :triple-des)

;; Variants
;; ECB mode encrypt
(defun triple-des-ecb-encrypt (plaintext key1 key2 key3)
  "Encrypt plaintext using Triple DES in ECB mode (EDE)."
  (let* ((step1 (des-api::encrypt-string-ecb plaintext key1))
	 (step2 (des-api::decrypt-string-ecb step1 key2)))
    (des-api::encrypt-string-ecb step2 key3)))

;; ECB mode decrypt
(defun triple-des-ecb-decrypt (ciphertext key1 key2 key3)
  "Decrypt ciphertext using Triple DES in ECB mode (EDE)."
  (let* ((step1 (des-api::decrypt-string-ecb ciphertext key3))
	 (step2 (des-api::encrypt-string-ecb step1 key2)))
    (des-api::decrypt-string-ecb step2 key1)))

;; CBC mode encrypt
(defun triple-des-cbc-encrypt (plaintext key1 key2 key3 iv)
  "Encrypt plaintext using Triple DES in CBC mode with existing DES primitives."
  (let* ((padded (pad-byte-vector (string-to-byte-vector plaintext) 8))
	 (blocks (split-into-blocks padded 8))
         (previous-block (ensure-bit-vector iv))
         result)
    (dolist (block blocks)
      (let* ((block (ensure-bit-vector block))
             ;; CBC XOR step
	     (xored (map 'bit-vector #'logxor block previous-block))
	     ;; DES IV chaining has to be performed only once!
	     ;; we can't use des-api::des-cbc-encrypt-string since it always uses iv
	     ;; and also it converts internal representations so we use ecb here again
	     
             ;; Triple DES encryption: E_k3(D_k2(E_k1(xored)))
	     (step1 (des-ecb-encrypt-block xored (generate-round-keys (ensure-bit-vector key1) t)))
             (step2 (des-ecb-decrypt-block step1 (generate-round-keys (ensure-bit-vector key2) t)))
             (cipher-block (des-ecb-encrypt-block step2 (generate-round-keys (ensure-bit-vector key3) t))))
        (push cipher-block result)
        (setf previous-block cipher-block)))
    ;; Convert bit-vectors to byte-vectors and flatten
    (apply #'concatenate 'vector
           (mapcar #'bit-vector-to-byte-vector (nreverse result)))))

;; CBC mode decrypt
(defun triple-des-cbc-decrypt (ciphertext key1 key2 key3 iv)
  "Decrypt ciphertext using Triple DES in CBC mode with existing DES primitives."
  (let* ((blocks (split-into-blocks ciphertext 8))
         (previous-block (ensure-bit-vector iv))
         result)
    (dolist (block blocks)
      (let* ((block (ensure-bit-vector block))
	     ;; DES IV chaining has to be performed only once!
	     ;; we can't use des-api::des-cbc-decrypt-string since it always uses iv.
	     ;; and also it converts internal representations so we use ecb here again.
	     ;; Other modes are streaming not chaining like CBC, so no special handling required there.
	     
             ;; Triple DES decryption: D_k1(E_k2(D_k3(block)))
	     (step1 (des-ecb-decrypt-block block (generate-round-keys (ensure-bit-vector key3) t)))
             (step2 (des-ecb-encrypt-block step1 (generate-round-keys (ensure-bit-vector key2) t)))
             (plaintext (des-ecb-decrypt-block step2 (generate-round-keys (ensure-bit-vector key1) t)))
             ;; CBC XOR step
	     (xored (map 'bit-vector #'logxor plaintext previous-block)))
        (push xored result)
        (setf previous-block block)))
    ;; Convert bit-vectors to byte-vectors and unpad
    (unpad-byte-vector
     (apply #'concatenate 'vector
            (mapcar #'bit-vector-to-byte-vector (nreverse result))))))

;; CFB mode mode encrypt 
(defun triple-des-cfb-encrypt (plaintext key1 key2 key3 iv)
  "Encrypt plaintext using Triple DES in CFB mode (EDE) with IV."
  (let* ((step1 (des-api::encrypt-string-cfb plaintext key1 iv))
	 (step2 (des-api::decrypt-string-cfb step1 key2 iv)))
    (des-api::encrypt-string-cfb step2 key3 iv)))

;; CFB mode decrypt
(defun triple-des-cfb-decrypt (ciphertext key1 key2 key3 iv)
  "Decrypt ciphertext using Triple DES in CFB mode (EDE) with IV."
  (let* ((step1 (des-api::decrypt-string-cfb ciphertext key3 iv))
	 (step2 (des-api::encrypt-string-cfb step1 key2 iv)))
    (des-api::decrypt-string-cfb step2 key1 iv)))

;; CFB8 mode encrypt
(defun triple-des-cfb8-encrypt (plaintext key1 key2 key3 iv)
  "Encrypt plaintext using Triple DES in CFB8 mode (EDE) with IV."
  (let* ((step1 (des-api::encrypt-string-cfb8 plaintext key1 iv))
	 (step2 (des-api::decrypt-string-cfb8 step1 key2 iv)))
    (des-api::encrypt-string-cfb8 step2 key3 iv)))

;; CFB8 mode decrypt
(defun triple-des-cfb8-decrypt (ciphertext key1 key2 key3 iv)
  "Decrypt ciphertext using Triple DES in CFB8 mode (EDE) with IV."
  (let* ((step1 (des-api::decrypt-string-cfb8 ciphertext key3 iv))
	 (step2 (des-api::encrypt-string-cfb8 step1 key2 iv)))
    (des-api::decrypt-string-cfb8 step2 key1 iv)))

;; CFB1 mode encrypt
(defun triple-des-cfb1-encrypt (plaintext key1 key2 key3 iv)
  "Encrypt plaintext using Triple DES in CFB1 mode (EDE) with IV."
  (let* ((step1 (des-api::encrypt-string-cfb1 plaintext key1 iv))
	 (step2 (des-api::decrypt-string-cfb1 step1 key2 iv)))
    (des-api::encrypt-string-cfb1 step2 key3 iv)))

;; CFB1 mode decrypt
(defun triple-des-cfb1-decrypt (ciphertext key1 key2 key3 iv)
  "Decrypt ciphertext using Triple DES in CFB1 mode (EDE) with IV."
  (let* ((step1 (des-api::decrypt-string-cfb1 ciphertext key3 iv))
	 (step2 (des-api::encrypt-string-cfb1 step1 key2 iv)))
    (des-api::decrypt-string-cfb1 step2 key1 iv)))

;; OFB mode encrypt
(defun triple-des-ofb-encrypt (plaintext key1 key2 key3 iv)
  "Encrypt plaintext using Triple DES in OFB mode (EDE) with IV."
  (let* ((step1 (des-api::encrypt-string-ofb plaintext key1 iv))
	 (step2 (des-api::decrypt-string-ofb step1 key2 iv)))
    (des-api::encrypt-string-ofb step2 key3 iv)))

;; OFB mode decrypt
(defun triple-des-ofb-decrypt (ciphertext key1 key2 key3 iv)
  "Decrypt ciphertext using Triple DES in OFB mode (EDE) with IV."
  (let* ((step1 (des-api::decrypt-string-ofb ciphertext key3 iv))
	 (step2 (des-api::encrypt-string-ofb step1 key2 iv)))
    (des-api::decrypt-string-ofb step2 key1 iv)))

;; CTR mode encrypt
(defun triple-des-ctr-encrypt (plaintext key1 key2 key3 iv)
  "Encrypt plaintext using Triple DES in CTR mode (EDE) with IV."
  (let* ((step1 (des-api::encrypt-string-ctr plaintext key1 iv))
	 (step2 (des-api::decrypt-string-ctr step1 key2 iv)))
    (des-api::encrypt-string-ctr step2 key3 iv)))

;; CTR mode decrypt
(defun triple-des-ctr-decrypt (ciphertext key1 key2 key3 iv)
  "Decrypt ciphertext using Triple DES in CTR mode (EDE) with IV."
  (let* ((step1 (des-api::decrypt-string-ctr ciphertext key3 iv))
	 (step2 (des-api::encrypt-string-ctr step1 key2 iv)))
    (des-api::decrypt-string-ctr step2 key1 iv)))

;; Base64
;; Base64 ECB mode encrypt
(defun triple-des-ecb-encrypt-base64 (plaintext key1 key2 key3)
  "Base64 Encrypt plaintext using Triple DES ECB (EDE)"
  (des-base64:string-to-base64
   (triple-des:triple-des-ecb-encrypt plaintext key1 key2 key3)))

;; Base64 ECB mode decrypt
(defun triple-des-ecb-decrypt-base64 (b64 key1 key2 key3)
  "Base64 Decrypt ciphertext using Triple DES ECB (EDE)"
  (triple-des:triple-des-ecb-decrypt
   (des-base64:base64-to-string b64) key1 key2 key3))

;; Base64 CBC mode encrypt
(defun triple-des-cbc-encrypt-base64 (plaintext key1 key2 key3 iv)
  "Base64 Encrypt plaintext using Triple DES CBC (EDE) with IV."
  (des-base64:string-to-base64
   (triple-des:triple-des-cbc-encrypt plaintext key1 key2 key3 iv)))

;; Base64 CBC mode decrypt
(defun triple-des-cbc-decrypt-base64 (b64 key1 key2 key3 iv)
  "Base64 Decrypt ciphertext using Triple DES CBC (EDE) with IV."
  (triple-des:triple-des-cbc-decrypt
   (des-base64:base64-to-string b64) key1 key2 key3 iv))

;; Base64 CFB mode encrypt
(defun triple-des-cfb-encrypt-base64 (plaintext key1 key2 key3 iv)
  "Base64 Encrypt plaintext using Triple DES CFB8 (EDE) with IV."
  (des-base64:string-to-base64
   (triple-des:triple-des-cfb-encrypt plaintext key1 key2 key3 iv)))

;; Base64 CFB mode decrypt
(defun triple-des-cfb-decrypt-base64 (b64 key1 key2 key3 iv)
  "Base64 Decrypt ciphertext using Triple DES CFB8 (EDE) with IV."
  (triple-des:triple-des-cfb-decrypt
   (des-base64:base64-to-string b64) key1 key2 key3 iv))

;; Base64 CFB8 mode encrypt
(defun triple-des-cfb8-encrypt-base64 (plaintext key1 key2 key3 iv)
  "Base64 Encrypt plaintext using Triple DES CFB8 (EDE) with IV."
  (des-base64:string-to-base64
   (triple-des:triple-des-cfb8-encrypt plaintext key1 key2 key3 iv)))

;; Base64 CFB8 mode decrypt
(defun triple-des-cfb8-decrypt-base64 (b64 key1 key2 key3 iv)
  "Base64 Decrypt ciphertext using Triple DES CFB8 (EDE) with IV."
  (triple-des:triple-des-cfb8-decrypt
   (des-base64:base64-to-string b64) key1 key2 key3 iv))

;; Base64 CBC1 mode encrypt
(defun triple-des-cfb1-encrypt-base64 (plaintext key1 key2 key3 iv)
  "Base64 Encrypt plaintext using Triple DES CFB1 (EDE) with IV."
  (des-base64:string-to-base64
   (triple-des:triple-des-cfb1-encrypt plaintext key1 key2 key3 iv)))

;; Base64 CBC1 mode decrypt
(defun triple-des-cfb1-decrypt-base64 (b64 key1 key2 key3 iv)
  "Base64 Decrypt ciphertext using Triple DES CFB1 (EDE) with IV."
  (triple-des:triple-des-cfb1-decrypt
   (des-base64:base64-to-string b64) key1 key2 key3 iv))

;; Base64 OFB mode encrypt
(defun triple-des-ofb-encrypt-base64 (plaintext key1 key2 key3 iv)
  "Base64 Encrypt plaintext using Triple DES OFB (EDE) with IV."
  (des-base64:string-to-base64
   (triple-des:triple-des-ofb-encrypt plaintext key1 key2 key3 iv)))

;; Base64 OFB mode decrypt
(defun triple-des-ofb-decrypt-base64 (b64 key1 key2 key3 iv)
  "Base64 Decrypt ciphertext using Triple DES OFB (EDE) with IV."
  (triple-des:triple-des-ofb-decrypt
   (des-base64:base64-to-string b64) key1 key2 key3 iv))

;; Base64 CTR mode encrypt
(defun triple-des-ctr-encrypt-base64 (plaintext key1 key2 key3 iv)
  "Base64 Encrypt plaintext using Triple DES CTR (EDE) with IV."
  (des-base64:string-to-base64
   (triple-des:triple-des-ctr-encrypt plaintext key1 key2 key3 iv)))

;; Base64 CTR mode decrypt
(defun triple-des-ctr-decrypt-base64 (b64 key1 key2 key3 iv)
  "Base64 Decrypt ciphertext using Triple DES CTR (EDE) with IV."
  (triple-des:triple-des-ctr-decrypt
   (des-base64:base64-to-string b64) key1 key2 key3 iv))

;; File Variants
;; ECB mode File encryption
(defun triple-des-ecb-encrypt-file (input-path output-path key1 key2 key3)
  "Encrypt file using Triple DES ECB mode (EDE)."
  (let ((plaintext (des-utils:read-file-as-string input-path)))
    (des-utils:write-string-to-file
     output-path
     (triple-des:triple-des-ecb-encrypt plaintext key1 key2 key3))))

;; ECB mode File decryption
(defun triple-des-ecb-decrypt-file (input-path output-path key1 key2 key3)
  "Decrypt file using Triple DES ECB mode (EDE)."
  (let ((ciphertext (des-utils:read-file-as-string input-path)))
    (des-utils:write-string-to-file
     output-path
     (triple-des:triple-des-ecb-decrypt ciphertext key1 key2 key3))))

;; CBC mode File encryption
(defun triple-des-cbc-encrypt-file (input-path output-path key1 key2 key3 iv)
  "Encrypt file using Triple DES CBC mode (EDE) with IV."
  (let ((plaintext (des-utils:read-file-as-string input-path)))
    (des-utils:write-string-to-file
     output-path
     (triple-des:triple-des-cbc-encrypt plaintext key1 key2 key3 iv))))

;; CBC mode File decryption
(defun triple-des-cbc-decrypt-file (input-path output-path key1 key2 key3 iv)
  "Decrypt file using Triple DES CBC mode (EDE) with IV."
  (let ((ciphertext (des-utils:read-file-as-string input-path)))
    (des-utils:write-string-to-file
     output-path
     (triple-des:triple-des-cbc-decrypt ciphertext key1 key2 key3 iv))))

;; CFB mode File encryption
(defun triple-des-cfb-encrypt-file (input-path output-path key1 key2 key3 iv)
  "Encrypt file using Triple DES CFB mode (EDE) with IV."
  (let ((plaintext (des-utils:read-file-as-string input-path)))
    (des-utils:write-string-to-file
     output-path
     (triple-des:triple-des-cfb-encrypt plaintext key1 key2 key3 iv))))

;; CFB mode File decryption
(defun triple-des-cfb-decrypt-file (input-path output-path key1 key2 key3 iv)
  "Decrypt file using Triple DES CFB mode (EDE) with IV."
  (let ((ciphertext (des-utils:read-file-as-string input-path)))
    (des-utils:write-string-to-file
     output-path
     (triple-des:triple-des-cfb-decrypt ciphertext key1 key2 key3 iv))))

;; CFB8 mode File encryption
(defun triple-des-cfb8-encrypt-file (input-path output-path key1 key2 key3 iv)
  "Encrypt file using Triple DES CFB8 mode (EDE) with IV."
  (let ((plaintext (des-utils:read-file-as-string input-path)))
    (des-utils:write-string-to-file
     output-path
     (triple-des:triple-des-cfb8-encrypt plaintext key1 key2 key3 iv))))

;; CFB8 mode File decryption
(defun triple-des-cfb8-decrypt-file (input-path output-path key1 key2 key3 iv)
  "Decrypt file using Triple DES CFB8 mode (EDE) with IV."
  (let ((ciphertext (des-utils:read-file-as-string input-path)))
    (des-utils:write-string-to-file
     output-path
     (triple-des:triple-des-cfb8-decrypt ciphertext key1 key2 key3 iv))))

;; CFB1 mode File encryption
(defun triple-des-cfb1-encrypt-file (input-path output-path key1 key2 key3 iv)
  "Encrypt file using Triple DES CFB1 mode (EDE) with IV."
  (let ((plaintext (des-utils:read-file-as-string input-path)))
    (des-utils:write-string-to-file
     output-path
     (triple-des:triple-des-cfb1-encrypt plaintext key1 key2 key3 iv))))

;; CFB1 mode File decryption
(defun triple-des-cfb1-decrypt-file (input-path output-path key1 key2 key3 iv)
  "Decrypt file using Triple DES CFB1 mode (EDE) with IV."
  (let ((ciphertext (des-utils:read-file-as-string input-path)))
    (des-utils:write-string-to-file
     output-path
     (triple-des:triple-des-cfb1-decrypt ciphertext key1 key2 key3 iv))))

;; OFB mode File encryption
(defun triple-des-ofb-encrypt-file (input-path output-path key1 key2 key3 iv)
  "Encrypt file using Triple DES OFB mode (EDE) with IV."
  (let ((plaintext (des-utils:read-file-as-string input-path)))
    (des-utils:write-string-to-file
     output-path
     (triple-des:triple-des-ofb-encrypt plaintext key1 key2 key3 iv))))

;; OFB mode File decryption
(defun triple-des-ofb-decrypt-file (input-path output-path key1 key2 key3 iv)
  "Decrypt file using Triple DES OFB mode (EDE) with IV."
  (let ((ciphertext (des-utils:read-file-as-string input-path)))
    (des-utils:write-string-to-file
     output-path
     (triple-des:triple-des-ofb-decrypt ciphertext key1 key2 key3 iv))))

;; CTR mode File encryption
(defun triple-des-ctr-encrypt-file (input-path output-path key1 key2 key3 iv)
  "Encrypt file using Triple DES CTR mode (EDE) with IV."
  (let ((plaintext (des-utils:read-file-as-string input-path)))
    (des-utils:write-string-to-file
     output-path
     (triple-des:triple-des-ctr-encrypt plaintext key1 key2 key3 iv))))

;; CTR mode File decryption
(defun triple-des-ctr-decrypt-file (input-path output-path key1 key2 key3 iv)
  "Decrypt file using Triple DES CTR mode (EDE) with IV."
  (let ((ciphertext (des-utils:read-file-as-string input-path)))
    (des-utils:write-string-to-file
     output-path
     (triple-des:triple-des-ctr-decrypt ciphertext key1 key2 key3 iv))))

;; Base64 File Variants
;; ECB mode Base64 File encryption
(defun triple-des-ecb-encrypt-file-base64 (input-path output-path key1 key2 key3)
  "Base64 Encrypt file using Triple DES ECB mode (EDE)."
  (let ((plaintext (des-utils:read-file-as-string input-path)))
    (des-utils:write-string-to-file
     output-path
     (triple-des:triple-des-ecb-encrypt-base64 plaintext key1 key2 key3))))

;; ECB mode Base64 File decryption
(defun triple-des-ecb-decrypt-file-base64 (input-path output-path key1 key2 key3)
  "Base64 Decrypt file using Triple DES ECB mode (EDE)."
  (let ((ciphertext (des-utils:read-file-as-string input-path)))
    (des-utils:write-string-to-file
     output-path
     (triple-des:triple-des-ecb-decrypt-base64 ciphertext key1 key2 key3))))

;; CBC mode Base64 File encryption
(defun triple-des-cbc-encrypt-file-base64 (input-path output-path key1 key2 key3 iv)
  "Base64 Encrypt file using Triple DES CBC mode (EDE) with IV."
  (let ((plaintext (des-utils:read-file-as-string input-path)))
    (des-utils:write-string-to-file
     output-path
     (triple-des:triple-des-cbc-encrypt-base64 plaintext key1 key2 key3 iv))))

;; CBC mode Base64 File decryption
(defun triple-des-cbc-decrypt-file-base64 (input-path output-path key1 key2 key3 iv)
  "Base64 Decrypt file using Triple DES CBC mode (EDE) with IV."
  (let ((ciphertext (des-utils:read-file-as-string input-path)))
    (des-utils:write-string-to-file
     output-path
     (triple-des:triple-des-cbc-decrypt-base64 ciphertext key1 key2 key3 iv))))

;; CFB mode Base64 File encryption
(defun triple-des-cfb-encrypt-file-base64 (input-path output-path key1 key2 key3 iv)
  "Base64 Encrypt file using Triple DES CFB mode (EDE) with IV."
  (let ((plaintext (des-utils:read-file-as-string input-path)))
    (des-utils:write-string-to-file
     output-path
     (triple-des:triple-des-cfb-encrypt-base64 plaintext key1 key2 key3 iv))))

;; CFB mode Base64 File decryption
(defun triple-des-cfb-decrypt-file-base64 (input-path output-path key1 key2 key3 iv)
  "Base64 Decrypt file using Triple DES CFB mode (EDE) with IV."
  (let ((ciphertext (des-utils:read-file-as-string input-path)))
    (des-utils:write-string-to-file
     output-path
     (triple-des:triple-des-cfb-decrypt-base64 ciphertext key1 key2 key3 iv))))

;; CFB8 mode Base64 File encryption
(defun triple-des-cfb8-encrypt-file-base64 (input-path output-path key1 key2 key3 iv)
  "Base64 Encrypt file using Triple DES CFB8 mode (EDE) with IV."
  (let ((plaintext (des-utils:read-file-as-string input-path)))
    (des-utils:write-string-to-file
     output-path
     (triple-des:triple-des-cfb8-encrypt-base64 plaintext key1 key2 key3 iv))))

;; CFB8 mode Base64 File decryption
(defun triple-des-cfb8-decrypt-file-base64 (input-path output-path key1 key2 key3 iv)
  "Base64 Decrypt file using Triple DES CFB8 mode (EDE) with IV."
  (let ((ciphertext (des-utils:read-file-as-string input-path)))
    (des-utils:write-string-to-file
     output-path
     (triple-des:triple-des-cfb8-decrypt-base64 ciphertext key1 key2 key3 iv))))

;; CFB1 mode Base64 File encryption
(defun triple-des-cfb1-encrypt-file-base64 (input-path output-path key1 key2 key3 iv)
  "Base64 Encrypt file using Triple DES CFB1 mode (EDE) with IV."
  (let ((plaintext (des-utils:read-file-as-string input-path)))
    (des-utils:write-string-to-file
     output-path
     (triple-des:triple-des-cfb1-encrypt-base64 plaintext key1 key2 key3 iv))))

;; CFB1 mode Base64 File decryption
(defun triple-des-cfb1-decrypt-file-base64 (input-path output-path key1 key2 key3 iv)
  "Base64 Decrypt file using Triple DES CFB1 mode (EDE) with IV."
  (let ((ciphertext (des-utils:read-file-as-string input-path)))
    (des-utils:write-string-to-file
     output-path
     (triple-des:triple-des-cfb1-decrypt-base64 ciphertext key1 key2 key3 iv))))

;; OFB mode Base64 File encryption
(defun triple-des-ofb-encrypt-file-base64 (input-path output-path key1 key2 key3 iv)
  "Base64 Encrypt file using Triple DES OFB mode (EDE) with IV."
  (let ((plaintext (des-utils:read-file-as-string input-path)))
    (des-utils:write-string-to-file
     output-path
     (triple-des:triple-des-ofb-encrypt-base64 plaintext key1 key2 key3 iv))))

;; OFB mode Base64 File decryption
(defun triple-des-ofb-decrypt-file-base64 (input-path output-path key1 key2 key3 iv)
  "Base64 Decrypt file using Triple DES OFB mode (EDE) with IV."
  (let ((ciphertext (des-utils:read-file-as-string input-path)))
    (des-utils:write-string-to-file
     output-path
     (triple-des:triple-des-ofb-decrypt-base64 ciphertext key1 key2 key3 iv))))

;; CTR mode Base64 File encryption
(defun triple-des-ctr-encrypt-file-base64 (input-path output-path key1 key2 key3 iv)
  "Base64 Encrypt file using Triple DES CTR mode (EDE) with IV."
  (let ((plaintext (des-utils:read-file-as-string input-path)))
    (des-utils:write-string-to-file
     output-path
     (triple-des:triple-des-ctr-encrypt-base64 plaintext key1 key2 key3 iv))))

;; CTR mode Base64 File decryption
(defun triple-des-ctr-decrypt-file-base64 (input-path output-path key1 key2 key3 iv)
  "Base64 Decrypt file using Triple DES CTR mode (EDE) with IV."
  (let ((ciphertext (des-utils:read-file-as-string input-path)))
    (des-utils:write-string-to-file
     output-path
     (triple-des:triple-des-ctr-decrypt-base64 ciphertext key1 key2 key3 iv))))
