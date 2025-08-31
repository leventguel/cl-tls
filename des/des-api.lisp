(defpackage :des-api
  (:use :cl :shared-utils :des-utils :des-padding :des-base64 :des-constants :des-core :des-context)
  (:export :encrypt-hex-ecb :decrypt-hex-ecb :encrypt-hex-cbc :decrypt-hex-cbc
	   :encrypt-hex-cfb :decrypt-hex-cfb :encrypt-hex-cfb8 :decrypt-hex-cfb8 :encrypt-hex-cfb1 :decrypt-hex-cfb1
	   :encrypt-hex-ofb :decrypt-hex-ofb :encrypt-hex-ctr :decrypt-hex-ctr
	   :encrypt-string-ecb :decrypt-string-ecb :encrypt-string-cbc :decrypt-string-cbc
	   :encrypt-string-cfb :decrypt-string-cfb :encrypt-string-cfb8 :decrypt-string-cfb8 :encrypt-string-cfb1 :decrypt-string-cfb1
	   :encrypt-string-ofb :decrypt-string-ofb :encrypt-string-ctr :decrypt-string-ctr
	   :encrypt-bytes-ecb :decrypt-bytes-ecb :encrypt-bytes-cbc :decrypt-bytes-cbc
	   :encrypt-bytes-cfb :decrypt-bytes-cfb :encrypt-bytes-cfb8 :decrypt-bytes-cfb8 :encrypt-bytes-cfb1 :decrypt-bytes-cfb1
	   :encrypt-bytes-ofb :decrypt-bytes-ofb :encrypt-bytes-ctr :decrypt-bytes-ctr
	   :encrypt-string-base64-ecb :decrypt-string-base64-ecb :encrypt-string-base64-cbc :decrypt-string-base64-cbc
	   :encrypt-string-base64-cfb :decrypt-string-base64-cfb :encrypt-string-base64-cfb8 :decrypt-string-base64-cfb8
	   :encrypt-string-base64-cfb1 :decrypt-string-base64-cfb1
	   :encrypt-string-base64-ofb :decrypt-string-base64-ofb :encrypt-string-base64-ctr :decrypt-string-base64-ctr
	   :encrypt-file-ecb :decrypt-file-ecb :encrypt-file-cbc :decrypt-file-cbc
	   :encrypt-file-cfb :decrypt-file-cfb :encrypt-file-cfb8 :decrypt-file-cfb8 :encrypt-file-cfb1 :decrypt-file-cfb1
	   :encrypt-file-ofb :decrypt-file-ofb :encrypt-file-ctr :decrypt-file-ctr
	   :encrypt-base64-file-ecb :decrypt-base64-file-ecb :encrypt-base64-file-cbc :decrypt-base64-file-cbc
	   :encrypt-base64-file-cfb :decrypt-base64-file-cfb :encrypt-base64-file-cfb8 :decrypt-base64-file-cfb8
	   :encrypt-base64-file-cfb1 :decrypt-base64-file-cfb1 :encrypt-base64-file-ofb :decrypt-base64-file-ofb
	   :encrypt-base64-file-ctr :decrypt-base64-file-ctr))

(in-package :des-api)

;; HexStrings
;; ECB mode for hex strings
(defun encrypt-hex-ecb (hex key &optional print)
  "Encrypt a hex string using DES ECB mode. Returns raw byte vector."
  (check-block-size hex)
  (let* ((bytes (hex-string-to-byte-vector hex))
         (cipher-blocks (des-ecb-encrypt bytes key)))
    (if print
	(apply #'concatenate 'string (mapcar #'byte-vector-to-hex-string cipher-blocks))
        cipher-blocks)))

;; ECB mode for hex strings
(defun decrypt-hex-ecb (encrypted-hex key)
  "Decrypt a DES ECB hex string and converts the raw byte vector to string(unpadded)."
  (check-block-size encrypted-hex)
  (let* ((plain-blocks (des-ecb-decrypt encrypted-hex key)))
    (byte-vector-to-string plain-blocks)))

;; CBC mode for hex string encryption
(defun encrypt-hex-cbc (hex key iv &optional print)
  "Encrypt a hex string using DES CBC mode. Returns raw byte vector."
  (check-block-size hex)
  (let* ((bytes (hex-string-to-byte-vector hex))
         (cipher-blocks (des-cbc-encrypt bytes key iv)))
    (if print
	(apply #'concatenate 'string (mapcar #'byte-vector-to-hex-string cipher-blocks))
	cipher-blocks)))

;; CBC mode for hex string decryption
(defun decrypt-hex-cbc (encrypted-hex key iv)
  "Decrypt a DES CBC hex string and converts the raw byte vector to string (unpadded)."
  (check-block-size encrypted-hex)
  (let* ((plain-blocks (des-cbc-decrypt encrypted-hex key iv)))
    (byte-vector-to-string plain-blocks)))

;; CFB mode for hex string encryption
(defun encrypt-hex-cfb (hex key iv &optional print)
  "Encrypt a hex string using DES CFB mode. Returns raw byte vector."
  (check-block-size hex)
  (let* ((bytes (hex-string-to-byte-vector hex))
	 (blocks (split-into-blocks bytes 8))
         (cipher-blocks (des-cfb-encrypt-plain blocks key iv)))
    (if print
	(apply #'concatenate 'string (mapcar #'byte-vector-to-hex-string cipher-blocks))
        cipher-blocks)))

;; CFB mode for hex string decryption
(defun decrypt-hex-cfb (encrypted-hex key iv)
  "Decrypt a DES CFB hex string and converts the raw byte vector to string (unpadded)."
  (let* ((plain-blocks (des-cfb-decrypt-plain encrypted-hex key iv)))
    (byte-vector-to-string plain-blocks)))

;; CFB8 mode for hex string encryption
(defun encrypt-hex-cfb8 (hex key iv &optional print)
  "Encrypt a hex string using DES CFB8 mode. Returns raw byte vector."
  (let* ((bytes (hex-string-to-byte-vector hex))
         (cipher-blocks (des-cfb8-encrypt-plain bytes key iv)))
    (if print
	(concatenate 'string (byte-vector-to-hex-string cipher-blocks))
        cipher-blocks)))

;; CFB8 mode for hex string decryption
(defun decrypt-hex-cfb8 (encrypted-hex key iv)
  "Decrypt a DES CFB8 hex string and converts the raw byte vector to string (unpadded)."
  (let* ((plain-blocks (des-cfb8-decrypt-plain encrypted-hex key iv)))
    (byte-vector-to-string plain-blocks)))

;; CFB1 mode for hex string encryption
(defun encrypt-hex-cfb1 (hex key iv &optional print)
  "Encrypt a hex string using DES CFB1 mode. Returns raw byte vector."
  (let* ((bytes (hex-string-to-byte-vector hex))
	 (bits (byte-vector-to-bitstream bytes))
         (cipher-bits (des-cfb1-encrypt-plain bits key iv)))
    (if print
	(format t "~{~A~}~%" cipher-bits)
        cipher-bits)))

(defun encrypt-hex-cfb1 (hex key iv &optional print)
  "Encrypt a hex string using DES CFB1 mode. Returns hex string."
  (let* ((bytes (hex-string-to-byte-vector hex))
         (bits (byte-vector-to-bitstream bytes))
         (cipher-bits (des-cfb1-encrypt-plain bits key iv))
         (cipher-bytes (bitstream-to-byte-vector cipher-bits))
         (cipher-hex (byte-vector-to-hex-string cipher-bytes)))
    (if print
	(format nil "~A" cipher-hex)
	cipher-hex)))

;; CFB1 mode for hex string decryption
(defun decrypt-hex-cfb1 (encrypted-hex key iv)
  "Decrypt a DES CFB1 hex string and convert the raw bitstream to string."
  (let* ((bytes (hex-string-to-byte-vector encrypted-hex))
         (bits (byte-vector-to-bitstream bytes))
         (plain-bits (des-cfb1-decrypt-plain bits key iv))
         (plain-bytes (bitstream-to-byte-vector plain-bits)))
    (byte-vector-to-string plain-bytes)))

;; OFB mode for hex string encryption
(defun encrypt-hex-ofb (hex key iv &optional print)
  "Encrypt a hex string using DES OFB mode. Returns raw byte vector."
  (let* ((bytes (hex-string-to-byte-vector hex))
         (cipher-blocks (des-ofb-encrypt-plain bytes key iv)))
    (if print
	(concatenate 'string (byte-vector-to-hex-string cipher-blocks))
        cipher-blocks)))

;; OFB mode for hex string decryption
(defun decrypt-hex-ofb (encrypted-hex key iv)
  "Decrypt a DES OFB hex string and converts the raw byte vector to string (unpadded)."
  (let* ((plain-blocks (des-ofb-decrypt-plain encrypted-hex key iv)))
    (byte-vector-to-string plain-blocks)))

;; CTR mode for hex string encryption
(defun encrypt-hex-ctr (hex key iv &optional print)
  "Encrypt a hex string using DES CTR mode. Returns raw byte vector."
  (let* ((bytes (hex-string-to-byte-vector hex))
         (cipher-blocks (des-ctr-encrypt-plain bytes key iv)))
    (if print
	(concatenate 'string (byte-vector-to-hex-string cipher-blocks))
        cipher-blocks)))

;; CTR mode for hex string decryption
(defun decrypt-hex-ctr (encrypted-hex key iv)
  "Decrypt a DES CTR hex string and converts the raw byte vector to string (unpadded)."
  (let* ((plain-blocks (des-ctr-decrypt-plain encrypted-hex key iv)))
    (byte-vector-to-string plain-blocks)))

;; Strings
;; ECB mode for string encryption
(defun encrypt-string-ecb (string key &optional print)
  "Encrypt a string using DES ECB mode. Returns raw byte vector."
  (let* ((bytes (string-to-byte-vector string))
	 (cipher-bytes (des-ecb-encrypt bytes key)))
    (if print
	(apply #'concatenate 'string (mapcar #'byte-vector-to-hex-string cipher-bytes))
	cipher-bytes)))

;; ECB mode for string decryption
(defun decrypt-string-ecb (encrypted-string key)
  "Decrypt a DES ECB string and converts the raw byte vector to string (unpadded)."
  (let* ((plain-bytes (des-ecb-decrypt encrypted-string key)))
    (byte-vector-to-string plain-bytes)))

;; CBC mode for string encryption
(defun encrypt-string-cbc (string key iv &optional print)
  "Encrypt a string using DES CBC mode. Returns raw byte vector."
  (let* ((bytes (string-to-byte-vector string))
	 (cipher-bytes (des-cbc-encrypt bytes key iv)))
    (if print
	(apply #'concatenate 'string (mapcar #'byte-vector-to-hex-string cipher-bytes))
	cipher-bytes)))

;; CBC mode for string decryption
(defun decrypt-string-cbc (encrypted-string key iv)
  "Decrypt a DES CBC string and converts the raw byte vector to string (unpadded)."
  (let* ((plain-bytes (des-cbc-decrypt encrypted-string key iv)))
    (byte-vector-to-string plain-bytes)))
    
;; CFB mode for string encryption
(defun encrypt-string-cfb (string key iv &optional print)
  "Encrypt a string using DES CFB mode. Returns raw byte vector."
  (let* ((bytes (string-to-byte-vector string))
	 (blocks (split-into-blocks bytes 8))
	 (cipher-bytes (des-cfb-encrypt-plain blocks key iv)))
    (if print
	(apply #'concatenate 'string (mapcar #'byte-vector-to-hex-string cipher-bytes))
	cipher-bytes)))

;; CFB mode for string decryption
(defun decrypt-string-cfb (encrypted-string key iv)
  "Decrypt a DES CFB string and converts the raw byte vector to string (unpadded)."
  (let* ((plain-bytes (des-cfb-decrypt-plain encrypted-string key iv)))
    (byte-vector-to-string plain-bytes)))

;; CFB8 mode for string encryption
(defun encrypt-string-cfb8 (string key iv &optional print)
  "Encrypt a string using DES CFB8 mode. Returns raw byte vector."
  (let* ((bytes (string-to-byte-vector string))
	 (cipher-bytes (des-cfb8-encrypt-plain bytes key iv)))
    (if print
	(concatenate 'string (byte-vector-to-hex-string cipher-bytes))
	cipher-bytes)))

;; CFB8 mode for string decryption
(defun decrypt-string-cfb8 (encrypted-string key iv)
  "Decrypt a DES CFB8 string and converts the raw byte vector to string (unpadded)."
  (let* ((plain-bytes (des-cfb8-decrypt-plain encrypted-string key iv)))
    (byte-vector-to-string plain-bytes)))

;; CFB1 mode for string encryption
(defun encrypt-string-cfb1 (string key iv &optional print)
  "Encrypt a string using DES CFB1 mode. Returns raw byte vector."
  (let* ((bytes (string-to-byte-vector string))
	 (bits (byte-vector-to-bitstream bytes))
	 (cipher-bits (des-cfb1-encrypt-plain bits key iv))
	 (cipher-bytes (bitstream-to-byte-vector cipher-bits))
	 (cipher-string (byte-vector-to-string cipher-bytes)))
    (if print
	(concatenate 'string (byte-vector-to-hex-string cipher-bytes))
	cipher-string)))

;; CFB1 mode for string decryption
(defun decrypt-string-cfb1 (encrypted-string key iv)
  "Decrypt a DES CFB1 string and convert the raw byte vector to string."
  (let* ((cipher-bytes (string-to-byte-vector encrypted-string))
         (cipher-bits (byte-vector-to-bitstream cipher-bytes))
         (plain-bits (des-cfb1-decrypt-plain cipher-bits key iv))
         (plain-bytes (bitstream-to-byte-vector plain-bits)))
    (byte-vector-to-string plain-bytes)))

;; OFB mode for string encryption
(defun encrypt-string-ofb (string key iv &optional print)
  "Encrypt a string using DES OFB mode. Returns raw byte vector."
  (let* ((bytes (string-to-byte-vector string))
	 (cipher-bytes (des-ofb-encrypt-plain bytes key iv)))
    (if print
	(concatenate 'string (byte-vector-to-hex-string cipher-bytes))
	cipher-bytes)))

;; OFB mode for string decryption
(defun decrypt-string-ofb (encrypted-string key iv)
  "Decrypt a DES OFB string and converts the raw byte vector to string (unpadded)."
  (let* ((plain-bytes (des-ofb-decrypt-plain encrypted-string key iv)))
    (byte-vector-to-string plain-bytes)))

;; CTR mode for string encryption
(defun encrypt-string-ctr (string key iv &optional print)
  "Encrypt a string using DES CTR mode. Returns raw byte vector."
  (let* ((bytes (string-to-byte-vector string))
	 (cipher-bytes (des-ctr-encrypt-plain bytes key iv)))
    (if print
	(concatenate 'string (byte-vector-to-hex-string cipher-bytes))
	cipher-bytes)))

;; CTR mode for string decryption
(defun decrypt-string-ctr (encrypted-string key iv)
  "Decrypt a DES CTR string and converts the raw byte vector to string (unpadded)."
  (let* ((plain-bytes (des-ctr-decrypt-plain encrypted-string key iv)))
    (byte-vector-to-string plain-bytes)))

;; Bytes
;; ECB mode for byte encryption
(defun encrypt-bytes-ecb (plain-bytes key &optional print)
  "Encrypts arbitrary-length byte vector using DES ECB with PKCS#7 padding."
  (let* ((key (ensure-bit-vector key))
	 (cipher-bytes (des-ecb-encrypt plain-bytes key)))
    (if print
	(apply #'concatenate 'string (mapcar #'byte-vector-to-hex-string cipher-bytes))
	cipher-bytes)))

;; ECB mode for byte decryption
(defun decrypt-bytes-ecb (cipher-bytes key)
  "Decrypts DES ECB-encrypted byte vector and removes PKCS#7 padding."
  (let* ((key (ensure-bit-vector key))
	 (plain-bytes (des-ecb-decrypt cipher-bytes key)))
    plain-bytes))

;; CBC mode for byte encryption
(defun encrypt-bytes-cbc (plain-bytes key iv &optional print)
  "Encrypts arbitrary-length byte vector using DES CBC with PKCS#7 padding."
  (let* ((cipher-blocks (des-cbc-encrypt plain-bytes key iv)))
    (if print
	(apply #'concatenate 'string (mapcar #'byte-vector-to-hex-string cipher-blocks))
	cipher-blocks)))

;; CBC mode for byte decryption
(defun decrypt-bytes-cbc (cipher-bytes key iv)
  "Decrypts DES CBC-encrypted byte vector and removes PKCS#7 padding."
  (let* ((plain-blocks (des-cbc-decrypt cipher-bytes key iv)))
    plain-blocks))

;; CFB mode for byte encryption
(defun encrypt-bytes-cfb (plain-bytes key iv &optional print)
  "Encrypts arbitrary-length byte vector using DES CFB with PKCS#7 padding."
  (let* ((plain-blocks (split-into-blocks plain-bytes 8))
	 (cipher-bytes (des-cfb-encrypt-plain plain-blocks key iv)))
    (if print
	(apply #'concatenate 'string (mapcar #'byte-vector-to-hex-string cipher-bytes))
	cipher-bytes)))

;; CFB mode for byte decryption
(defun decrypt-bytes-cfb (cipher-bytes key iv)
  "Decrypts DES CFB-encrypted byte vector and removes PKCS#7 padding."
  (let* ((plain-blocks (des-cfb-decrypt-plain cipher-bytes key iv)))
    plain-blocks))

;; CFB8 mode for byte encryption
(defun encrypt-bytes-cfb8 (plain-bytes key iv &optional print)
  "Encrypts arbitrary-length byte vector using DES CFB8 with PKCS#7 padding."
  (let* ((cipher-blocks (des-cfb8-encrypt-plain plain-bytes key iv)))
    (if print
	(concatenate 'string (byte-vector-to-hex-string cipher-blocks))
	cipher-blocks)))

;; CFB8 mode for byte decryption
(defun decrypt-bytes-cfb8 (cipher-bytes key iv)
  "Decrypts DES CFB8-encrypted byte vector and removes PKCS#7 padding."
  (let* ((plain-blocks (des-cfb8-decrypt-plain cipher-bytes key iv)))
    plain-blocks))

;; CFB1 mode for byte encryption
(defun encrypt-bytes-cfb1 (plain-bytes key iv &optional print)
  "Encrypts arbitrary-length byte vector using DES CFB1 with PKCS#7 padding."
  (let* ((plain-bits (byte-vector-to-bitstream plain-bytes))
	 (cipher-bits (des-cfb1-encrypt-plain plain-bits key iv))
	 (cipher-bytes (bitstream-to-byte-vector cipher-bits)))
    (if print
	(byte-vector-to-hex-string cipher-bytes)
	cipher-bytes)))

;; CFB1 mode for byte decryption
(defun decrypt-bytes-cfb1 (cipher-bytes key iv)
  "Decrypts DES CFB1-encrypted byte vector and removes PKCS#7 padding."
  (let* ((cipher-bits (byte-vector-to-bitstream cipher-bytes))
         (plain-bits (des-cfb1-decrypt-plain cipher-bits key iv))
         (plain-bytes (bitstream-to-byte-vector plain-bits)))
    plain-bytes))

;; OFB mode for byte encryption
(defun encrypt-bytes-ofb (plain-bytes key iv &optional print)
  "Encrypts arbitrary-length byte vector using DES OFB with PKCS#7 padding."
  (let* ((cipher-blocks (des-ofb-encrypt-plain plain-bytes key iv)))
    (if print
	(concatenate 'string (byte-vector-to-hex-string cipher-blocks))
	cipher-blocks)))

;; OFB mode for byte decryption
(defun decrypt-bytes-ofb (cipher-bytes key iv)
  "Decrypts DES OFB-encrypted byte vector and removes PKCS#7 padding."
  (let* ((plain-blocks (des-ofb-decrypt-plain cipher-bytes key iv)))
    plain-blocks))

;; CTR mode for byte encryption
(defun encrypt-bytes-ctr (plain-bytes key iv &optional print)
  "Encrypts arbitrary-length byte vector using DES CTR with PKCS#7 padding."
  (let* ((cipher-blocks (des-ctr-encrypt-plain plain-bytes key iv)))
    (if print
	(concatenate 'string (byte-vector-to-hex-string cipher-blocks))
	cipher-blocks)))

;; CTR mode for byte decryption
(defun decrypt-bytes-ctr (cipher-bytes key iv)
  "Decrypts DES CTR-encrypted byte vector and removes PKCS#7 padding."
  (let* ((plain-blocks (des-ctr-decrypt-plain cipher-bytes key iv)))
    plain-blocks))

;; Base64 Strings
;; ECB mode for base64 strings
(defun encrypt-string-base64-ecb (str key)
  "Encrypts a string using DES ECB and returns Base64-encoded ciphertext."
  (let* ((key (ensure-bit-vector key))
	 (plain-bytes (string-to-byte-vector str))
         (cipher-blocks (encrypt-bytes-ecb plain-bytes key))
         (cipher-bytes (apply #'concatenate 'vector cipher-blocks)))
    (base64-encode cipher-bytes)))

;; ECB mode for base64 strings
(defun decrypt-string-base64-ecb (b64 key)
  "Decrypt a Base64-encoded DES ECB ciphertext string."
  (let* ((key (ensure-bit-vector key))
         (cipher-bytes (des-base64:base64-decode b64))
         (blocks (split-into-blocks cipher-bytes 8))
         (bit-blocks (mapcar #'byte-vector-to-bit-vector blocks))
         (plain-bytes (decrypt-bytes-ecb bit-blocks key)))
    (byte-vector-to-string plain-bytes)))

;; CBC mode for base64 string encryption
(defun encrypt-string-base64-cbc (str key iv)
  "Encrypts a string using DES CBC and returns Base64-encoded ciphertext."
  (let* ((key (ensure-bit-vector key))
	 (iv (ensure-bit-vector iv))
	 (plain-bytes (string-to-byte-vector str))
         (cipher-blocks (encrypt-bytes-cbc plain-bytes key iv))
         (cipher-bytes (apply #'concatenate 'vector cipher-blocks)))
    (base64-encode cipher-bytes)))

;; CBC mode for base64 string decryption
(defun decrypt-string-base64-cbc (b64 key iv)
  "Decrypt a Base64-encoded DES CBC ciphertext string."
  (let* ((key (ensure-bit-vector key)) ;; it suffices to only convert one of key or iv here
         (cipher-bytes (des-base64:base64-decode b64))
         (blocks (split-into-blocks cipher-bytes 8))
         (bit-blocks (mapcar #'byte-vector-to-bit-vector blocks))
         (plain-bytes (decrypt-bytes-cbc bit-blocks key iv)))
    (byte-vector-to-string plain-bytes)))

;; CFB mode for base64 string encryption
(defun encrypt-string-base64-cfb (str key iv)
  "Encrypts a string using DES CFB and returns Base64-encoded ciphertext."
  (let* ((key (ensure-bit-vector key))
	 (iv (ensure-bit-vector iv))
	 (plain-bytes (string-to-byte-vector str))
         (cipher-blocks (encrypt-bytes-cfb plain-bytes key iv))
         (cipher-bytes (apply #'concatenate 'vector cipher-blocks)))
    (base64-encode cipher-bytes)))

;; CFB mode for base64 strings decryption
(defun decrypt-string-base64-cfb (b64 key iv)
  "Decrypt a Base64-encoded DES CFB ciphertext string."
  (let* ((key (ensure-bit-vector key)) ;; it suffices to only convert one of key or iv here
         (cipher-bytes (des-base64:base64-decode b64))
         (blocks (split-into-blocks cipher-bytes 8))
         (plain-bytes (decrypt-bytes-cfb blocks key iv)))
    (byte-vector-to-string plain-bytes)))

;; CFB8 mode for base64 string encryption
(defun encrypt-string-base64-cfb8 (str key iv)
  "Encrypts a string using DES CFB8 and returns Base64-encoded ciphertext."
  (let* ((key (ensure-bit-vector key))
	 (iv (ensure-bit-vector iv))
	 (plain-bytes (string-to-byte-vector str))
         (cipher-blocks (encrypt-bytes-cfb8 plain-bytes key iv))
         (cipher-bytes (concatenate 'vector cipher-blocks)))
    (base64-encode cipher-bytes)))

(defun decrypt-string-base64-cfb8 (b64 key iv)
  "Decrypt a Base64-encoded DES CFB8 ciphertext string."
  (let* ((key (ensure-bit-vector key))
         (cipher-bytes (des-base64:base64-decode b64))
         (plain-bytes (decrypt-bytes-cfb8 cipher-bytes key iv)))
    (byte-vector-to-string plain-bytes)))

;; CFB1 mode for base64 string encryption
(defun encrypt-string-base64-cfb1 (str key iv)
  "Encrypts a string using DES CFB1 and returns Base64-encoded ciphertext."
  (let* ((key (ensure-bit-vector key))
	 (iv (ensure-bit-vector iv))
	 (plain-bytes (string-to-byte-vector str))
         (cipher-blocks (encrypt-bytes-cfb1 plain-bytes key iv))
         (cipher-bytes (concatenate 'vector cipher-blocks)))
    (base64-encode cipher-bytes)))

;; CFB1 mode for base64 strings decryption
(defun decrypt-string-base64-cfb1 (b64 key iv)
  "Decrypt a Base64-encoded DES CFB1 ciphertext string."
  (let* ((key (ensure-bit-vector key)) ;; it suffices to only convert one of key or iv here
         (cipher-bytes (des-base64:base64-decode b64))
         (plain-bytes (decrypt-bytes-cfb1 cipher-bytes key iv)))
    (byte-vector-to-string plain-bytes)))

;; OFB mode for base64 string encryption
(defun encrypt-string-base64-ofb (str key iv)
  "Encrypts a string using DES OFB and returns Base64-encoded ciphertext."
  (let* ((key (ensure-bit-vector key))
	 (iv (ensure-bit-vector iv))
	 (plain-bytes (string-to-byte-vector str))
         (cipher-blocks (encrypt-bytes-ofb plain-bytes key iv))
         (cipher-bytes (concatenate 'vector cipher-blocks)))
    (base64-encode cipher-bytes)))

;; OFB mode for base64 strings decryption
(defun decrypt-string-base64-ofb (b64 key iv)
  "Decrypt a Base64-encoded DES OFB ciphertext string."
  (let* ((key (ensure-bit-vector key)) ;; it suffices to only convert one of key or iv here
         (cipher-bytes (des-base64:base64-decode b64))
         (plain-bytes (decrypt-bytes-ofb cipher-bytes key iv)))
    (byte-vector-to-string plain-bytes)))

;; CTR mode for base64 string encryption
(defun encrypt-string-base64-ctr (str key iv)
  "Encrypts a string using DES CTR and returns Base64-encoded ciphertext."
  (let* ((key (ensure-bit-vector key))
         (iv (ensure-byte-vector iv)) ;; ← changed here
         (plain-bytes (string-to-byte-vector str))
         (cipher-blocks (encrypt-bytes-ctr plain-bytes key iv))
         (cipher-bytes (concatenate 'vector cipher-blocks)))
    (base64-encode cipher-bytes)))

;; CTR mode for base64 strings decryption
(defun decrypt-string-base64-ctr (b64 key iv)
  "Decrypt a Base64-encoded DES CTR ciphertext string."
  (let* ((key (ensure-bit-vector key))
         (iv (ensure-byte-vector iv)) ;; ← changed here
         (cipher-bytes (des-base64:base64-decode b64))
         (plain-bytes (decrypt-bytes-ctr cipher-bytes key iv)))
    (byte-vector-to-string plain-bytes)))

;; Files
;; ECB mode for file encryption
(defun encrypt-file-ecb (input-path output-path key)
  "Encrypts a file with ECB mode DES"
  (handler-case
      (with-open-file (in input-path :direction :input :element-type '(unsigned-byte 8))
	(with-open-file (out output-path :direction :output :element-type '(unsigned-byte 8)
                             :if-exists :supersede :if-does-not-exist :create)
	  ;; NOTE: We avoid UTF-8 and encoding errors by treating all encrypted data as raw bytes. read-sequence/write-sequence
	  ;; - Files are read/written using byte vectors, not strings.
	  ;; - No implicit character decoding is applied to ciphertext.
	  ;; - This ensures roundtrip integrity and prevents decoding exceptions.
	  (let* ((length (file-length in))
		 (buffer (make-array length :element-type '(unsigned-byte 8)))
		 (bytes (progn (read-sequence buffer in) buffer))
		 (cipher-blocks (encrypt-bytes-ecb bytes key))
		 (cipher-bytes (apply #'concatenate 'vector cipher-blocks)))
	    (write-sequence cipher-bytes out)
	  :success)))
    (error (e)
      (format t "ECB mode encrypt File error: ~A~%" e))))

;; ECB mode for file decryption
(defun decrypt-file-ecb (input-path output-path key)
  "Decrypts a file with ECB mode DES"
  (handler-case
      (with-open-file (in input-path :direction :input :element-type '(unsigned-byte 8))
	(with-open-file (out output-path :direction :output :element-type '(unsigned-byte 8)
			     :if-exists :supersede :if-does-not-exist :create)
	  ;; NOTE: We avoid UTF-8 and encoding errors by treating all encrypted data as raw bytes. read-sequence/write-sequence
	  ;; - Files are read/written using byte vectors, not strings.
	  ;; - No implicit character decoding is applied to ciphertext.
	  ;; - This ensures roundtrip integrity and prevents decoding exceptions.
	  (let* ((length (file-length in))
		 (buffer (make-array length :element-type '(unsigned-byte 8)))
		 (bytes (progn (read-sequence buffer in) buffer))
		 ;; Split into 8-byte blocks and convert to bit-vectors
		 (blocks (split-into-blocks bytes 8))
		 (bit-blocks (mapcar #'byte-vector-to-bit-vector blocks))
		 (plain-bytes (decrypt-bytes-ecb bit-blocks key)))
	    (write-sequence plain-bytes out)
	    :success)))
    (error (e)
      (format t "ECB mode decrypt File error: ~A~%" e))))

;; CBC mode for file encryption
(defun encrypt-file-cbc (input-path output-path key iv)
  "Encrypts a file with CBC mode DES"
  (handler-case
      (with-open-file (in input-path :direction :input :element-type '(unsigned-byte 8))
	(with-open-file (out output-path :direction :output :element-type '(unsigned-byte 8)
                             :if-exists :supersede :if-does-not-exist :create)
	  ;; NOTE: We avoid UTF-8 and encoding errors by treating all encrypted data as raw bytes. read-sequence/write-sequence
	  ;; - Files are read/written using byte vectors, not strings.
	  ;; - No implicit character decoding is applied to ciphertext.
	  ;; - This ensures roundtrip integrity and prevents decoding exceptions.
	  (let* ((length (file-length in))
		 (buffer (make-array length :element-type '(unsigned-byte 8)))
		 (bytes (progn (read-sequence buffer in) buffer))
		 (cipher-blocks (encrypt-bytes-cbc bytes key iv))
		 (cipher-bytes (apply #'concatenate 'vector cipher-blocks)))
	    (write-sequence cipher-bytes out)
	  :success)))
    (error (e)
      (format t "CBC mode encrypt File error: ~A~%" e))))

;; CBC mode for file decryption
(defun decrypt-file-cbc (input-path output-path key iv)
  "Decrypts a file with CBC mode DES"
  (handler-case
      (with-open-file (in input-path :direction :input :element-type '(unsigned-byte 8))
	(with-open-file (out output-path :direction :output :element-type '(unsigned-byte 8)
			     :if-exists :supersede :if-does-not-exist :create)
	  ;; NOTE: We avoid UTF-8 and encoding errors by treating all encrypted data as raw bytes. read-sequence/write-sequence
	  ;; - Files are read/written using byte vectors, not strings.
	  ;; - No implicit character decoding is applied to ciphertext.
	  ;; - This ensures roundtrip integrity and prevents decoding exceptions.
	  (let* ((length (file-length in))
		 (buffer (make-array length :element-type '(unsigned-byte 8)))
		 (bytes (progn (read-sequence buffer in) buffer))
		 ;; Split into 8-byte blocks and convert to bit-vectors
		 (blocks (split-into-blocks bytes 8))
		 (bit-blocks (mapcar #'byte-vector-to-bit-vector blocks))
		 (plain-bytes (decrypt-bytes-cbc bit-blocks key iv)))
	    (write-sequence plain-bytes out)
	    :success)))
    (error (e)
      (format t "CBC mode decrypt File error: ~A~%" e))))


;; CFB mode for file encryption
(defun encrypt-file-cfb (input-path output-path key iv)
  "Encrypts a file with CFB mode DES"
  (handler-case
      (with-open-file (in input-path :direction :input :element-type '(unsigned-byte 8))
	(with-open-file (out output-path :direction :output :element-type '(unsigned-byte 8)
                             :if-exists :supersede :if-does-not-exist :create)
	  ;; NOTE: We avoid UTF-8 and encoding errors by treating all encrypted data as raw bytes. read-sequence/write-sequence
	  ;; - Files are read/written using byte vectors, not strings.
	  ;; - No implicit character decoding is applied to ciphertext.
	  ;; - This ensures roundtrip integrity and prevents decoding exceptions.
	  (let* ((length (file-length in))
		 (buffer (make-array length :element-type '(unsigned-byte 8)))
		 (bytes (progn (read-sequence buffer in) buffer))
		 (cipher-blocks (encrypt-bytes-cfb bytes key iv))
		 (cipher-bytes (apply #'concatenate 'vector cipher-blocks)))
	    (write-sequence cipher-bytes out)
	  :success)))
    (error (e)
      (format t "CFB mode encrypt File error: ~A~%" e))))

;; CFB mode for file decryption
(defun decrypt-file-cfb (input-path output-path key iv)
  "Decrypts a file with CFB mode DES"
  (handler-case
      (with-open-file (in input-path :direction :input :element-type '(unsigned-byte 8))
	(with-open-file (out output-path :direction :output :element-type '(unsigned-byte 8)
			     :if-exists :supersede :if-does-not-exist :create)
	  ;; NOTE: We avoid UTF-8 and encoding errors by treating all encrypted data as raw bytes. read-sequence/write-sequence
	  ;; - Files are read/written using byte vectors, not strings.
	  ;; - No implicit character decoding is applied to ciphertext.
	  ;; - This ensures roundtrip integrity and prevents decoding exceptions.
	  (let* ((length (file-length in))
		 (buffer (make-array length :element-type '(unsigned-byte 8)))
		 (bytes (progn (read-sequence buffer in) buffer))
		 ;; Split into 8-byte blocks and convert to bit-vectors
		 (blocks (split-into-blocks bytes 8))
		 (plain-bytes (decrypt-bytes-cfb blocks key iv)))
	    (write-sequence plain-bytes out)
	    :success)))
    (error (e)
      (format t "CFB mode decrypt File error: ~A~%" e))))

;; CFB8 mode for file encryption
(defun encrypt-file-cfb8 (input-path output-path key iv)
  "Encrypts a file with CFB8 mode DES"
  (handler-case
      (with-open-file (in input-path :direction :input :element-type '(unsigned-byte 8))
	(with-open-file (out output-path :direction :output :element-type '(unsigned-byte 8)
                             :if-exists :supersede :if-does-not-exist :create)
	  ;; NOTE: We avoid UTF-8 and encoding errors by treating all encrypted data as raw bytes. read-sequence/write-sequence
	  ;; - Files are read/written using byte vectors, not strings.
	  ;; - No implicit character decoding is applied to ciphertext.
	  ;; - This ensures roundtrip integrity and prevents decoding exceptions.
	  (let* ((length (file-length in))
		 (buffer (make-array length :element-type '(unsigned-byte 8)))
		 (bytes (progn (read-sequence buffer in) buffer))
		 (cipher-blocks (encrypt-bytes-cfb8 bytes key iv))
		 (cipher-bytes (concatenate 'vector cipher-blocks)))
	    (write-sequence cipher-bytes out)
	  :success)))
    (error (e)
      (format t "CFB8 mode encrypt File error: ~A~%" e))))

;; CFB8 mode for file decryption
(defun decrypt-file-cfb8 (input-path output-path key iv)
  "Decrypts a file with CFB8 mode DES"
  (handler-case
      (with-open-file (in input-path :direction :input :element-type '(unsigned-byte 8))
	(with-open-file (out output-path :direction :output :element-type '(unsigned-byte 8)
			     :if-exists :supersede :if-does-not-exist :create)
	  ;; NOTE: We avoid UTF-8 and encoding errors by treating all encrypted data as raw bytes. read-sequence/write-sequence
	  ;; - Files are read/written using byte vectors, not strings.
	  ;; - No implicit character decoding is applied to ciphertext.
	  ;; - This ensures roundtrip integrity and prevents decoding exceptions.
	  (let* ((length (file-length in))
		 (buffer (make-array length :element-type '(unsigned-byte 8)))
		 (bytes (progn (read-sequence buffer in) buffer))
		 (plain-bytes (decrypt-bytes-cfb8 bytes key iv)))
	    (write-sequence plain-bytes out)
	    :success)))
    (error (e)
      (format t "CFB8 mode decrypt File error: ~A~%" e))))

;; CFB1 mode for file encryption
(defun encrypt-file-cfb1 (input-path output-path key iv)
  "Encrypts a file with CFB1 mode DES"
  (handler-case
      (with-open-file (in input-path :direction :input :element-type '(unsigned-byte 8))
	(with-open-file (out output-path :direction :output :element-type '(unsigned-byte 8)
                             :if-exists :supersede :if-does-not-exist :create)
	  ;; NOTE: We avoid UTF-8 and encoding errors by treating all encrypted data as raw bytes. read-sequence/write-sequence
	  ;; - Files are read/written using byte vectors, not strings.
	  ;; - No implicit character decoding is applied to ciphertext.
	  ;; - This ensures roundtrip integrity and prevents decoding exceptions.
	  (let* ((length (file-length in))
		 (buffer (make-array length :element-type '(unsigned-byte 8)))
		 (bytes (progn (read-sequence buffer in) buffer))
		 (cipher-blocks (encrypt-bytes-cfb1 bytes key iv))
		 (cipher-bytes (concatenate 'vector cipher-blocks)))
	    (write-sequence cipher-bytes out)
	  :success)))
    (error (e)
      (format t "CFB1 mode encrypt File error: ~A~%" e))))

;; CFB1 mode for file decryption
(defun decrypt-file-cfb1 (input-path output-path key iv)
  "Decrypts a file with CFB1 mode DES"
  (handler-case
      (with-open-file (in input-path :direction :input :element-type '(unsigned-byte 8))
	(with-open-file (out output-path :direction :output :element-type '(unsigned-byte 8)
			     :if-exists :supersede :if-does-not-exist :create)
	  ;; NOTE: We avoid UTF-8 and encoding errors by treating all encrypted data as raw bytes. read-sequence/write-sequence
	  ;; - Files are read/written using byte vectors, not strings.
	  ;; - No implicit character decoding is applied to ciphertext.
	  ;; - This ensures roundtrip integrity and prevents decoding exceptions.
	  (let* ((length (file-length in))
		 (buffer (make-array length :element-type '(unsigned-byte 8)))
		 (bytes (progn (read-sequence buffer in) buffer))
		 (plain-bytes (decrypt-bytes-cfb1 bytes key iv)))
	    (write-sequence plain-bytes out)
	    :success)))
    (error (e)
      (format t "CFB1 mode decrypt File error: ~A~%" e))))

;; OFB mode for file encryption
(defun encrypt-file-ofb (input-path output-path key iv)
  "Encrypts a file with OFB mode DES"
  (handler-case
      (with-open-file (in input-path :direction :input :element-type '(unsigned-byte 8))
	(with-open-file (out output-path :direction :output :element-type '(unsigned-byte 8)
                             :if-exists :supersede :if-does-not-exist :create)
	  ;; NOTE: We avoid UTF-8 and encoding errors by treating all encrypted data as raw bytes. read-sequence/write-sequence
	  ;; - Files are read/written using byte vectors, not strings.
	  ;; - No implicit character decoding is applied to ciphertext.
	  ;; - This ensures roundtrip integrity and prevents decoding exceptions.
	  (let* ((length (file-length in))
		 (buffer (make-array length :element-type '(unsigned-byte 8)))
		 (bytes (progn (read-sequence buffer in) buffer))
		 (cipher-blocks (encrypt-bytes-ofb bytes key iv))
		 (cipher-bytes (concatenate 'vector cipher-blocks)))
	    (write-sequence cipher-bytes out)
	  :success)))
    (error (e)
      (format t "OFB mode encrypt File error: ~A~%" e))))

;; OFB mode for file decryption
(defun decrypt-file-ofb (input-path output-path key iv)
  "Decrypts a file with OFB mode DES"
  (handler-case
      (with-open-file (in input-path :direction :input :element-type '(unsigned-byte 8))
	(with-open-file (out output-path :direction :output :element-type '(unsigned-byte 8)
			     :if-exists :supersede :if-does-not-exist :create)
	  ;; NOTE: We avoid UTF-8 and encoding errors by treating all encrypted data as raw bytes. read-sequence/write-sequence
	  ;; - Files are read/written using byte vectors, not strings.
	  ;; - No implicit character decoding is applied to ciphertext.
	  ;; - This ensures roundtrip integrity and prevents decoding exceptions.
	  (let* ((length (file-length in))
		 (buffer (make-array length :element-type '(unsigned-byte 8)))
		 (bytes (progn (read-sequence buffer in) buffer))
		 (plain-bytes (decrypt-bytes-ofb bytes key iv)))
	    (write-sequence plain-bytes out)
	    :success)))
    (error (e)
      (format t "OFB mode decrypt File error: ~A~%" e))))

;; CTR mode for file encryption
(defun encrypt-file-ctr (input-path output-path key iv)
  "Encrypts a file with CTR mode DES"
  (handler-case
      (with-open-file (in input-path :direction :input :element-type '(unsigned-byte 8))
	(with-open-file (out output-path :direction :output :element-type '(unsigned-byte 8)
                             :if-exists :supersede :if-does-not-exist :create)
	  ;; NOTE: We avoid UTF-8 and encoding errors by treating all encrypted data as raw bytes. read-sequence/write-sequence
	  ;; - Files are read/written using byte vectors, not strings.
	  ;; - No implicit character decoding is applied to ciphertext.
	  ;; - This ensures roundtrip integrity and prevents decoding exceptions.
	  (let* ((length (file-length in))
		 (buffer (make-array length :element-type '(unsigned-byte 8)))
		 (bytes (progn (read-sequence buffer in) buffer))
		 (cipher-blocks (encrypt-bytes-ctr bytes key iv))
		 (cipher-bytes (concatenate 'vector cipher-blocks)))
	    (write-sequence cipher-bytes out)
	  :success)))
    (error (e)
      (format t "CTR mode encrypt File error: ~A~%" e))))

;; CTR mode for file decryption
(defun decrypt-file-ctr (input-path output-path key iv)
  "Decrypts a file with CTR mode DES"
  (handler-case
      (with-open-file (in input-path :direction :input :element-type '(unsigned-byte 8))
	(with-open-file (out output-path :direction :output :element-type '(unsigned-byte 8)
			     :if-exists :supersede :if-does-not-exist :create)
	  ;; NOTE: We avoid UTF-8 and encoding errors by treating all encrypted data as raw bytes. read-sequence/write-sequence
	  ;; - Files are read/written using byte vectors, not strings.
	  ;; - No implicit character decoding is applied to ciphertext.
	  ;; - This ensures roundtrip integrity and prevents decoding exceptions.
	  (let* ((length (file-length in))
		 (buffer (make-array length :element-type '(unsigned-byte 8)))
		 (bytes (progn (read-sequence buffer in) buffer))
		 (plain-bytes (decrypt-bytes-ctr bytes key iv)))
	    (write-sequence plain-bytes out)
	    :success)))
    (error (e)
      (format t "CTR mode decrypt File error: ~A~%" e))))

;; Base64 Files
;; ECB mode base64 file encryption
(defun encrypt-base64-file-ecb (input-path output-path key)
  "Encrypts a file with ECB mode DES and outputs base64-encoded ciphertext."
  ;; NOTE: We treat the file as raw bytes to support arbitrary binary content.
  ;; - This avoids character encoding issues (e.g., UTF-8 decoding errors).
  ;; - Ensures full file content is encrypted, not just one line.
  ;; - Base64 encoding makes the output safe for text-based storage.
  (handler-case
      (with-open-file (in input-path :direction :input :element-type '(unsigned-byte 8))
        (with-open-file (out output-path :direction :output :if-exists :supersede :if-does-not-exist :create)
          (let* ((length (file-length in))
                 (buffer (make-array length :element-type '(unsigned-byte 8)))
                 (bytes (progn (read-sequence buffer in) buffer))
                 (cipher-bytes (encrypt-bytes-ecb bytes key))
                 (b64 (des-base64:base64-encode (apply #'concatenate 'vector cipher-bytes))))
            (write-line b64 out)
            :success)))
    (error (e)
      (format t "Base64 ECB mode encrypt File error: ~A~%" e))))

;; ECB mode base64 file decryption
(defun decrypt-base64-file-ecb (input-path output-path key)
  "Decrypts a base64-encoded file using CBC mode DES."
  (handler-case
      (with-open-file (in input-path :direction :input)
        (with-open-file (out output-path :direction :output :element-type '(unsigned-byte 8)
                             :if-exists :supersede :if-does-not-exist :create)
	  ;; NOTE: This version assumes the input file contains a single line of base64-encoded ciphertext.
	  ;; - Uses `read-line` to read the encoded string as text.
	  ;; - Decodes base64 into a flat byte vector.
	  ;; - Splits the byte vector into 8-byte blocks for CBC decryption.
	  ;; - `decrypt-bytes-cbc` expects a list of blocks, not a flat vector.
	  ;; - Output is written using `write-sequence` with `(unsigned-byte 8)` to preserve raw bytes.
	  ;; - No character decoding is applied to the decrypted output — this avoids UTF-8 errors.
	  ;; - Assumes padding is handled internally by the CBC decryption logic.
          (let* ((b64-line (read-line in))
                 ;; Decode base64 to byte vector — no apply needed
                 (cipher-bytes (des-base64:base64-decode b64-line))
		 (cipher-blocks (split-into-blocks cipher-bytes 8))
                 ;; Decrypt directly on byte vector
                 (plain-bytes (decrypt-bytes-ecb cipher-blocks key)))
            ;; Write decrypted bytes to output file
            (write-sequence plain-bytes out)
            :success)))
    (error (e)
      (format t "Base64 ECB mode decrypt File error: ~A~%" e))))

;; CBC mode base64 file encryption
(defun encrypt-base64-file-cbc (input-path output-path key iv)
  "Encrypts a file with CBC mode DES and outputs base64-encoded ciphertext."
  ;; NOTE: 
  ;; - Encrypted output is a vector of bytes, which is base64-encoded for safe storage.
  ;; - We use `(apply #'concatenate 'vector ...)` because `encrypt-bytes-cbc` returns a list of blocks.
  ;;   This flattens the result into a single byte vector for encoding.
  ;; - No character encoding is applied to ciphertext — base64 handles binary safely.
  ;; NOTE: We treat the file as raw bytes to support arbitrary binary content.
  ;; - This avoids character encoding issues (e.g., UTF-8 decoding errors).
  ;; - Ensures full file content is encrypted, not just one line.
  ;; - Base64 encoding makes the output safe for text-based storage.
  (handler-case
      (with-open-file (in input-path :direction :input :element-type '(unsigned-byte 8))
        (with-open-file (out output-path :direction :output :if-exists :supersede :if-does-not-exist :create)
          (let* ((length (file-length in))
                 (buffer (make-array length :element-type '(unsigned-byte 8)))
                 (bytes (progn (read-sequence buffer in) buffer))
                 (cipher-bytes (encrypt-bytes-cbc bytes key iv))
                 (b64 (des-base64:base64-encode (apply #'concatenate 'vector cipher-bytes))))
            (write-line b64 out)
            :success)))
    (error (e)
      (format t "Base64 CBC mode encrypt File error: ~A~%" e))))

;; CBC mode base64 file decryption
(defun decrypt-base64-file-cbc (input-path output-path key iv)
  "Decrypts a base64-encoded file using CBC mode DES."
  (handler-case
      (with-open-file (in input-path :direction :input)
        (with-open-file (out output-path :direction :output :element-type '(unsigned-byte 8)
                             :if-exists :supersede :if-does-not-exist :create)
	  ;; NOTE: This version assumes the input file contains a single line of base64-encoded ciphertext.
	  ;; - Uses `read-line` to read the encoded string as text.
	  ;; - Decodes base64 into a flat byte vector.
	  ;; - Splits the byte vector into 8-byte blocks for CBC decryption.
	  ;; - `decrypt-bytes-cbc` expects a list of blocks, not a flat vector.
	  ;; - Output is written using `write-sequence` with `(unsigned-byte 8)` to preserve raw bytes.
	  ;; - No character decoding is applied to the decrypted output — this avoids UTF-8 errors.
	  ;; - Assumes padding is handled internally by the CBC decryption logic.
          (let* ((b64-line (read-line in))
                 ;; Decode base64 to byte vector — no apply needed
                 (cipher-bytes (des-base64:base64-decode b64-line))
		 (cipher-blocks (split-into-blocks cipher-bytes 8))
                 ;; Decrypt directly on byte vector
                 (plain-bytes (decrypt-bytes-cbc cipher-blocks key iv)))
            ;; Write decrypted bytes to output file
            (write-sequence plain-bytes out)
            :success)))
    (error (e)
      (format t "Base64 CBC mode decrypt File error: ~A~%" e))))

;; CFB mode base64 file encryption
(defun encrypt-base64-file-cfb (input-path output-path key iv)
  "Encrypts a file with CFB mode DES and outputs base64-encoded ciphertext."
  ;; NOTE: 
  ;; - Encrypted output is a vector of bytes, which is base64-encoded for safe storage.
  ;; - We use `(apply #'concatenate 'vector ...)` because `encrypt-bytes-cbc` returns a list of blocks.
  ;;   This flattens the result into a single byte vector for encoding.
  ;; - No character encoding is applied to ciphertext — base64 handles binary safely.
  ;; NOTE: We treat the file as raw bytes to support arbitrary binary content.
  ;; - This avoids character encoding issues (e.g., UTF-8 decoding errors).
  ;; - Ensures full file content is encrypted, not just one line.
  ;; - Base64 encoding makes the output safe for text-based storage.
  (handler-case
      (with-open-file (in input-path :direction :input :element-type '(unsigned-byte 8))
        (with-open-file (out output-path :direction :output :if-exists :supersede :if-does-not-exist :create)
          (let* ((length (file-length in))
                 (buffer (make-array length :element-type '(unsigned-byte 8)))
                 (bytes (progn (read-sequence buffer in) buffer))
                 (cipher-bytes (encrypt-bytes-cfb bytes key iv))
                 (b64 (des-base64:base64-encode (apply #'concatenate 'vector cipher-bytes))))
            (write-line b64 out)
            :success)))
    (error (e)
      (format t "Base64 CFB mode encrypt File error: ~A~%" e))))

;; CFB mode base64 file decryption
(defun decrypt-base64-file-cfb (input-path output-path key iv)
  "Decrypts a base64-encoded file using CFB mode DES."
  (handler-case
      (with-open-file (in input-path :direction :input)
        (with-open-file (out output-path :direction :output :element-type '(unsigned-byte 8)
			     :if-exists :supersede :if-does-not-exist :create)
	  ;; NOTE: This version assumes the input file contains a single line of base64-encoded ciphertext.
	  ;; - Uses `read-line` to read the encoded string as text.
	  ;; - Decodes base64 into a flat byte vector.
	  ;; - Splits the byte vector into 8-byte blocks for CBC decryption.
	  ;; - `decrypt-bytes-cbc` expects a list of blocks, not a flat vector.
	  ;; - Output is written using `write-sequence` with `(unsigned-byte 8)` to preserve raw bytes.
	  ;; - No character decoding is applied to the decrypted output — this avoids UTF-8 errors.
	  ;; - Assumes padding is handled internally by the CBC decryption logic.
          (let* ((b64-line (read-line in))
                 ;; Decode base64 to byte vector — no apply needed
                 (cipher-bytes (des-base64:base64-decode b64-line))
		 (cipher-blocks (split-into-blocks cipher-bytes 8))
                 ;; Decrypt directly on byte vector
                 (plain-bytes (decrypt-bytes-cfb cipher-blocks key iv)))
            ;; Write decrypted bytes to output file
            (write-sequence plain-bytes out)
            :success)))
    (error (e)
      (format t "Base64 CFB mode decrypt File error: ~A~%" e))))

;; CFB8 mode base64 file encryption
(defun encrypt-base64-file-cfb8 (input-path output-path key iv)
  "Encrypts a file with CFB8 mode DES and outputs base64-encoded ciphertext."
  ;; NOTE: 
  ;; - Encrypted output is a vector of bytes, which is base64-encoded for safe storage.
  ;; - We use `(apply #'concatenate 'vector ...)` because `encrypt-bytes-cbc` returns a list of blocks.
  ;;   This flattens the result into a single byte vector for encoding.
  ;; - No character encoding is applied to ciphertext — base64 handles binary safely.
  ;; NOTE: We treat the file as raw bytes to support arbitrary binary content.
  ;; - This avoids character encoding issues (e.g., UTF-8 decoding errors).
  ;; - Ensures full file content is encrypted, not just one line.
  ;; - Base64 encoding makes the output safe for text-based storage.
  (handler-case
      (with-open-file (in input-path :direction :input :element-type '(unsigned-byte 8))
        (with-open-file (out output-path :direction :output :if-exists :supersede :if-does-not-exist :create)
          (let* ((length (file-length in))
                 (buffer (make-array length :element-type '(unsigned-byte 8)))
                 (bytes (progn (read-sequence buffer in) buffer))
                 (cipher-bytes (encrypt-bytes-cfb8 bytes key iv))
                 (b64 (des-base64:base64-encode (concatenate 'vector cipher-bytes))))
            (write-line b64 out)
            :success)))
    (error (e)
      (format t "Base64 CFB8 mode encrypt File error: ~A~%" e))))

;; CFB8 mode base64 file decryption
(defun decrypt-base64-file-cfb8 (input-path output-path key iv)
  "Decrypts a base64-encoded file using CFB8 mode DES."
  (handler-case
      (with-open-file (in input-path :direction :input)
        (with-open-file (out output-path :direction :output :element-type '(unsigned-byte 8)
                             :if-exists :supersede :if-does-not-exist :create)
	  ;; NOTE: This version assumes the input file contains a single line of base64-encoded ciphertext.
	  ;; - Uses `read-line` to read the encoded string as text.
	  ;; - Decodes base64 into a flat byte vector.
	  ;; - Splits the byte vector into 8-byte blocks for CBC decryption.
	  ;; - `decrypt-bytes-cbc` expects a list of blocks, not a flat vector.
	  ;; - Output is written using `write-sequence` with `(unsigned-byte 8)` to preserve raw bytes.
	  ;; - No character decoding is applied to the decrypted output — this avoids UTF-8 errors.
	  ;; - Assumes padding is handled internally by the CBC decryption logic.
          (let* ((b64-line (read-line in))
                 ;; Decode base64 to byte vector — no apply needed
                 (cipher-bytes (des-base64:base64-decode b64-line))
                 ;; Decrypt directly on byte vector
                 (plain-bytes (decrypt-bytes-cfb8 cipher-bytes key iv)))
            ;; Write decrypted bytes to output file
            (write-sequence plain-bytes out)
            :success)))
    (error (e)
      (format t "Base64 CFB8 mode decrypt File error: ~A~%" e))))

;; CFB1 mode base64 file encryption
(defun encrypt-base64-file-cfb1 (input-path output-path key iv)
  "Encrypts a file with CFB1 mode DES and outputs base64-encoded ciphertext."
  ;; NOTE: 
  ;; - Encrypted output is a vector of bytes, which is base64-encoded for safe storage.
  ;; - We use `(apply #'concatenate 'vector ...)` because `encrypt-bytes-cbc` returns a list of blocks.
  ;;   This flattens the result into a single byte vector for encoding.
  ;; - No character encoding is applied to ciphertext — base64 handles binary safely.
  ;; NOTE: We treat the file as raw bytes to support arbitrary binary content.
  ;; - This avoids character encoding issues (e.g., UTF-8 decoding errors).
  ;; - Ensures full file content is encrypted, not just one line.
  ;; - Base64 encoding makes the output safe for text-based storage.
  (handler-case
      (with-open-file (in input-path :direction :input :element-type '(unsigned-byte 8))
        (with-open-file (out output-path :direction :output :if-exists :supersede :if-does-not-exist :create)
          (let* ((length (file-length in))
                 (buffer (make-array length :element-type '(unsigned-byte 8)))
                 (bytes (progn (read-sequence buffer in) buffer))
                 (cipher-bytes (encrypt-bytes-cfb1 bytes key iv))
                 (b64 (des-base64:base64-encode (concatenate 'vector cipher-bytes))))
            (write-line b64 out)
            :success)))
    (error (e)
      (format t "Base64 CFB1 mode encrypt File error: ~A~%" e))))

;; CFB1 mode base64 file decryption
(defun decrypt-base64-file-cfb1 (input-path output-path key iv)
  "Decrypts a base64-encoded file using CFB8 mode DES."
  (handler-case
      (with-open-file (in input-path :direction :input)
        (with-open-file (out output-path :direction :output :element-type '(unsigned-byte 8)
                             :if-exists :supersede :if-does-not-exist :create)
	  ;; NOTE: This version assumes the input file contains a single line of base64-encoded ciphertext.
	  ;; - Uses `read-line` to read the encoded string as text.
	  ;; - Decodes base64 into a flat byte vector.
	  ;; - Splits the byte vector into 8-byte blocks for CBC decryption.
	  ;; - `decrypt-bytes-cbc` expects a list of blocks, not a flat vector.
	  ;; - Output is written using `write-sequence` with `(unsigned-byte 8)` to preserve raw bytes.
	  ;; - No character decoding is applied to the decrypted output — this avoids UTF-8 errors.
	  ;; - Assumes padding is handled internally by the CBC decryption logic.
          (let* ((b64-line (read-line in))
                 ;; Decode base64 to byte vector — no apply needed
                 (cipher-bytes (des-base64:base64-decode b64-line))
                 ;; Decrypt directly on byte vector
                 (plain-bytes (decrypt-bytes-cfb1 cipher-bytes key iv)))
            ;; Write decrypted bytes to output file
            (write-sequence plain-bytes out)
            :success)))
    (error (e)
      (format t "Base64 CFB1 mode decrypt File error: ~A~%" e))))

;; OFB mode base64 file encryption
(defun encrypt-base64-file-ofb (input-path output-path key iv)
  "Encrypts a file with OFB mode DES and outputs base64-encoded ciphertext."
  ;; NOTE: 
  ;; - Encrypted output is a vector of bytes, which is base64-encoded for safe storage.
  ;; - We use `(apply #'concatenate 'vector ...)` because `encrypt-bytes-cbc` returns a list of blocks.
  ;;   This flattens the result into a single byte vector for encoding.
  ;; - No character encoding is applied to ciphertext — base64 handles binary safely.
  ;; NOTE: We treat the file as raw bytes to support arbitrary binary content.
  ;; - This avoids character encoding issues (e.g., UTF-8 decoding errors).
  ;; - Ensures full file content is encrypted, not just one line.
  ;; - Base64 encoding makes the output safe for text-based storage.
  (handler-case
      (with-open-file (in input-path :direction :input :element-type '(unsigned-byte 8))
        (with-open-file (out output-path :direction :output :if-exists :supersede :if-does-not-exist :create)
          (let* ((length (file-length in))
                 (buffer (make-array length :element-type '(unsigned-byte 8)))
                 (bytes (progn (read-sequence buffer in) buffer))
                 (cipher-bytes (encrypt-bytes-ofb bytes key iv))
                 (b64 (des-base64:base64-encode (concatenate 'vector cipher-bytes))))
            (write-line b64 out)
            :success)))
    (error (e)
      (format t "Base64 OFB mode encrypt File error: ~A~%" e))))

;; OFB mode base64 file decryption
(defun decrypt-base64-file-ofb (input-path output-path key iv)
  "Decrypts a base64-encoded file using OFB mode DES."
  (handler-case
      (with-open-file (in input-path :direction :input)
        (with-open-file (out output-path :direction :output :element-type '(unsigned-byte 8)
                             :if-exists :supersede :if-does-not-exist :create)
	  ;; NOTE: This version assumes the input file contains a single line of base64-encoded ciphertext.
	  ;; - Uses `read-line` to read the encoded string as text.
	  ;; - Decodes base64 into a flat byte vector.
	  ;; - Splits the byte vector into 8-byte blocks for CBC decryption.
	  ;; - `decrypt-bytes-cbc` expects a list of blocks, not a flat vector.
	  ;; - Output is written using `write-sequence` with `(unsigned-byte 8)` to preserve raw bytes.
	  ;; - No character decoding is applied to the decrypted output — this avoids UTF-8 errors.
	  ;; - Assumes padding is handled internally by the CBC decryption logic.
          (let* ((b64-line (read-line in))
                 ;; Decode base64 to byte vector — no apply needed
                 (cipher-bytes (des-base64:base64-decode b64-line))
                 ;; Decrypt directly on byte vector
                 (plain-bytes (decrypt-bytes-ofb cipher-bytes key iv)))
            ;; Write decrypted bytes to output file
            (write-sequence plain-bytes out)
            :success)))
    (error (e)
      (format t "Base64 OFB mode decrypt File error: ~A~%" e))))

;; CTR mode base64 file encryption
(defun encrypt-base64-file-ctr (input-path output-path key iv)
  "Encrypts a file with CTR mode DES and outputs base64-encoded ciphertext."
  ;; NOTE: 
  ;; - Encrypted output is a vector of bytes, which is base64-encoded for safe storage.
  ;; - We use `(apply #'concatenate 'vector ...)` because `encrypt-bytes-cbc` returns a list of blocks.
  ;;   This flattens the result into a single byte vector for encoding.
  ;; - No character encoding is applied to ciphertext — base64 handles binary safely.
  ;; NOTE: We treat the file as raw bytes to support arbitrary binary content.
  ;; - This avoids character encoding issues (e.g., UTF-8 decoding errors).
  ;; - Ensures full file content is encrypted, not just one line.
  ;; - Base64 encoding makes the output safe for text-based storage.
  (handler-case
      (with-open-file (in input-path :direction :input :element-type '(unsigned-byte 8))
        (with-open-file (out output-path :direction :output :if-exists :supersede :if-does-not-exist :create)
          (let* ((length (file-length in))
                 (buffer (make-array length :element-type '(unsigned-byte 8)))
                 (bytes (progn (read-sequence buffer in) buffer))
                 (cipher-bytes (encrypt-bytes-ctr bytes key iv))
                 (b64 (des-base64:base64-encode (concatenate 'vector cipher-bytes))))
            (write-line b64 out)
            :success)))
    (error (e)
      (format t "Base64 CTR mode encrypt File error: ~A~%" e))))

;; CTR mode base64 file decryption
(defun decrypt-base64-file-ctr (input-path output-path key iv)
  "Decrypts a base64-encoded file using CTR mode DES."
  (handler-case
      (with-open-file (in input-path :direction :input)
        (with-open-file (out output-path :direction :output :element-type '(unsigned-byte 8)
                             :if-exists :supersede :if-does-not-exist :create)
	  ;; NOTE: This version assumes the input file contains a single line of base64-encoded ciphertext.
	  ;; - Uses `read-line` to read the encoded string as text.
	  ;; - Decodes base64 into a flat byte vector.
	  ;; - Splits the byte vector into 8-byte blocks for CBC decryption.
	  ;; - `decrypt-bytes-cbc` expects a list of blocks, not a flat vector.
	  ;; - Output is written using `write-sequence` with `(unsigned-byte 8)` to preserve raw bytes.
	  ;; - No character decoding is applied to the decrypted output — this avoids UTF-8 errors.
	  ;; - Assumes padding is handled internally by the CBC decryption logic.
          (let* ((b64-line (read-line in))
                 ;; Decode base64 to byte vector — no apply needed
                 (cipher-bytes (des-base64:base64-decode b64-line))
                 ;; Decrypt directly on byte vector
                 (plain-bytes (decrypt-bytes-ctr cipher-bytes key iv)))
            ;; Write decrypted bytes to output file
            (write-sequence plain-bytes out)
            :success)))
    (error (e)
      (format t "Base64 CTR mode decrypt File error: ~A~%" e))))
