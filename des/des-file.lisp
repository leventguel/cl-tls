(defpackage :des-file
  (:use :cl :des-utils :des-padding :des-constants :des-core :des-api)
  (:export :ensure-generated-files-dir
	   :test-file-ecb-roundtrip :test-file-ecb-roundtrip-multiline
	   :test-file-cbc-roundtrip :test-file-cbc-roundtrip-multiline
	   :test-file-cfb-roundtrip :test-file-cfb-roundtrip-multiline
	   :test-file-cfb8-roundtrip :test-file-cfb8-roundtrip-multiline
	   :test-file-cfb1-roundtrip :test-file-cfb1-roundtrip-multiline
	   :test-file-ofb-roundtrip :test-file-ofb-roundtrip-multiline
	   :test-file-ctr-roundtrip :test-file-ctr-roundtrip-multiline
	   :test-file-base64-ecb-roundtrip :test-file-base64-ecb-roundtrip-multiline
	   :test-file-base64-cbc-roundtrip :test-file-base64-cbc-roundtrip-multiline
	   :test-file-base64-cfb-roundtrip :test-file-base64-cfb-roundtrip-multiline
	   :test-file-base64-cfb8-roundtrip :test-file-base64-cfb8-roundtrip-multiline
	   :test-file-base64-cfb1-roundtrip :test-file-base64-cfb1-roundtrip-multiline
	   :test-file-base64-ofb-roundtrip :test-file-base64-ofb-roundtrip-multiline
	   :test-file-base64-ctr-roundtrip :test-file-base64-ctr-roundtrip-multiline))

(in-package :des-file)

(defun ensure-generated-files-dir ()
  (let ((dir "generated-files/"))
    (ensure-directories-exist dir)))

(defun test-file-ecb-roundtrip ()
  (ensure-generated-files-dir)
  (let* ((key #(1 2 3 4 5 6 7 8))
         (input-path "generated-files/test-input-ecb.txt")
         (encrypted-path "generated-files/test-encrypted-ecb.bin")
         (decrypted-path "generated-files/test-decrypted-ecb.txt"))
    ;; Write single-line file
    (with-open-file (out input-path :direction :output :if-exists :supersede :if-does-not-exist :create)
      (write-line "Hello File ECB World!" out))

    ;; Encrypt and decrypt
    (des-api::encrypt-file-ecb input-path encrypted-path key)
    (des-api::decrypt-file-ecb encrypted-path decrypted-path key)

    ;; Compare contents
    (with-open-file (in decrypted-path :direction :input)
      (let ((line (read-line in)))
        (format t "Decrypted file content: ~A~%" line)
        (string= line "Hello File ECB World!")))))

(defun test-file-ecb-roundtrip-multiline ()
  (ensure-generated-files-dir)
  (let* ((key #(1 2 3 4 5 6 7 8))
         (input-path "generated-files/test-input-ecb-multiline.txt")
         (encrypted-path "generated-files/test-encrypted-ecb-multiline.bin")
         (decrypted-path "generated-files/test-decrypted-ecb-multiline.txt")
         (lines '("Hello File ECB World!"
                  "This is line two."
                  "Third line with symbols: @#$%^&*()"
                  "日本語の行もテストします。")))
    ;; Write multi-line input file
    (with-open-file (out input-path :direction :output :if-exists :supersede :if-does-not-exist :create)
      (dolist (line lines)
        (write-line line out)))

    ;; Encrypt and decrypt
    (des-api::encrypt-file-ecb input-path encrypted-path key)
    (des-api::decrypt-file-ecb encrypted-path decrypted-path key)

    ;; Compare contents line-by-line
    (with-open-file (in decrypted-path :direction :input)
      (loop for expected in lines
            for actual = (read-line in nil)
            always (string= expected actual)))))

(defun test-file-cbc-roundtrip ()
  (ensure-generated-files-dir)
  (let* ((key #(1 2 3 4 5 6 7 8))
         (iv #(0 0 0 0 0 0 0 0))
         (input-path "generated-files/test-input-cbc.txt")
         (encrypted-path "generated-files/test-encrypted-cbc.bin")
         (decrypted-path "generated-files/test-decrypted-cbc.txt"))
    ;; Write test file
    (with-open-file (out input-path :direction :output :if-exists :supersede :if-does-not-exist :create)
      (write-line "Hello File CBC World!" out))
    ;; Encrypt and decrypt
    (des-api::encrypt-file-cbc input-path encrypted-path key iv)
    (des-api::decrypt-file-cbc encrypted-path decrypted-path key iv)
    ;; Compare contents
    (with-open-file (in decrypted-path :direction :input)
      (let ((line (read-line in)))
        (format t "Decrypted file content: ~A~%" line)
        (string= line "Hello File CBC World!")))))

(defun test-file-cbc-roundtrip-multiline ()
  (ensure-generated-files-dir)
  (let* ((key #(1 2 3 4 5 6 7 8))
         (iv #(0 0 0 0 0 0 0 0))
         (input-path "generated-files/test-input-cbc-multiline.txt")
         (encrypted-path "generated-files/test-encrypted-cbc-multiline.bin")
         (decrypted-path "generated-files/test-decrypted-cbc-multiline.txt")
         (lines '("Hello File CBC World!"
                  "This is line two."
                  "Third line with symbols: @#$%^&*()"
                  "日本語の行もテストします。")))
    ;; Write multi-line input file
    (with-open-file (out input-path :direction :output :if-exists :supersede :if-does-not-exist :create)
      (dolist (line lines)
        (write-line line out)))

    ;; Encrypt and decrypt
    (des-api::encrypt-file-cbc input-path encrypted-path key iv)
    (des-api::decrypt-file-cbc encrypted-path decrypted-path key iv)

    ;; Compare contents line-by-line
    (with-open-file (in decrypted-path :direction :input)
      (loop for expected in lines
            for actual = (read-line in nil)
            always (string= expected actual)))))

(defun test-file-cfb-roundtrip ()
  (ensure-generated-files-dir)
  (let* ((key #(1 2 3 4 5 6 7 8))
         (iv #(0 0 0 0 0 0 0 0))
         (input-path "generated-files/test-input-cfb.txt")
         (encrypted-path "generated-files/test-encrypted-cfb.bin")
         (decrypted-path "generated-files/test-decrypted-cfb.txt"))
    ;; Write test file
    (with-open-file (out input-path :direction :output :if-exists :supersede :if-does-not-exist :create)
      (write-line "Hello File CFB World!" out))
    ;; Encrypt and decrypt
    (des-api::encrypt-file-cfb input-path encrypted-path key iv)
    (des-api::decrypt-file-cfb encrypted-path decrypted-path key iv)
    ;; Compare contents
    (with-open-file (in decrypted-path :direction :input)
      (let ((line (read-line in)))
        (format t "Decrypted file content: ~A~%" line)
        (string= line "Hello File CFB World!")))))

(defun test-file-cfb-roundtrip-multiline ()
  (ensure-generated-files-dir)
  (let* ((key #(1 2 3 4 5 6 7 8))
         (iv #(0 0 0 0 0 0 0 0))
         (input-path "generated-files/test-input-cfb-multiline.txt")
         (encrypted-path "generated-files/test-encrypted-cfb-multiline.bin")
         (decrypted-path "generated-files/test-decrypted-cfb-multiline.txt")
         (lines '("Hello File CFB World!"
                  "This is line two."
                  "Third line with symbols: @#$%^&*()"
                  "日本語の行もテストします。")))
    ;; Write multi-line input file
    (with-open-file (out input-path :direction :output :if-exists :supersede :if-does-not-exist :create)
      (dolist (line lines)
        (write-line line out)))

    ;; Encrypt and decrypt
    (des-api::encrypt-file-cfb input-path encrypted-path key iv)
    (des-api::decrypt-file-cfb encrypted-path decrypted-path key iv)

    ;; Compare contents line-by-line
    (with-open-file (in decrypted-path :direction :input)
      (loop for expected in lines
            for actual = (read-line in nil)
            always (string= expected actual)))))

(defun test-file-cfb8-roundtrip ()
  (ensure-generated-files-dir)
  (let* ((key #(1 2 3 4 5 6 7 8))
         (iv #(0 0 0 0 0 0 0 0))
         (input-path "generated-files/test-input-cfb8.txt")
         (encrypted-path "generated-files/test-encrypted-cfb8.bin")
         (decrypted-path "generated-files/test-decrypted-cfb8.txt"))
    ;; Write test file
    (with-open-file (out input-path :direction :output :if-exists :supersede :if-does-not-exist :create)
      (write-line "Hello File CFB8 World!" out))
    ;; Encrypt and decrypt
    (des-api::encrypt-file-cfb8 input-path encrypted-path key iv)
    (des-api::decrypt-file-cfb8 encrypted-path decrypted-path key iv)
    ;; Compare contents
    (with-open-file (in decrypted-path :direction :input)
      (let ((line (read-line in)))
        (format t "Decrypted file content: ~A~%" line)
        (string= line "Hello File CFB8 World!")))))

(defun test-file-cfb8-roundtrip-multiline ()
  (ensure-generated-files-dir)
  (let* ((key #(1 2 3 4 5 6 7 8))
         (iv #(0 0 0 0 0 0 0 0))
         (input-path "generated-files/test-input-cfb8-multiline.txt")
         (encrypted-path "generated-files/test-encrypted-cfb8-multiline.bin")
         (decrypted-path "generated-files/test-decrypted-cfb8-multiline.txt")
         (lines '("Hello File CFB8 World!"
                  "This is line two."
                  "Third line with symbols: @#$%^&*()"
                  "日本語の行もテストします。")))
    ;; Write multi-line input file
    (with-open-file (out input-path :direction :output :if-exists :supersede :if-does-not-exist :create)
      (dolist (line lines)
        (write-line line out)))

    ;; Encrypt and decrypt
    (des-api::encrypt-file-cfb8 input-path encrypted-path key iv)
    (des-api::decrypt-file-cfb8 encrypted-path decrypted-path key iv)

    ;; Compare contents line-by-line
    (with-open-file (in decrypted-path :direction :input)
      (loop for expected in lines
            for actual = (read-line in nil)
            always (string= expected actual)))))

(defun test-file-cfb1-roundtrip ()
  (ensure-generated-files-dir)
  (let* ((key #(1 2 3 4 5 6 7 8))
         (iv #(0 0 0 0 0 0 0 0))
         (input-path "generated-files/test-input-cfb1.txt")
         (encrypted-path "generated-files/test-encrypted-cfb1.bin")
         (decrypted-path "generated-files/test-decrypted-cfb1.txt"))
    ;; Write test file
    (with-open-file (out input-path :direction :output :if-exists :supersede :if-does-not-exist :create)
      (write-line "Hello File CFB1 World!" out))
    ;; Encrypt and decrypt
    (des-api::encrypt-file-cfb1 input-path encrypted-path key iv)
    (des-api::decrypt-file-cfb1 encrypted-path decrypted-path key iv)
    ;; Compare contents
    (with-open-file (in decrypted-path :direction :input)
      (let ((line (read-line in)))
        (format t "Decrypted file content: ~A~%" line)
        (string= line "Hello File CFB1 World!")))))

(defun test-file-cfb1-roundtrip-multiline ()
  (ensure-generated-files-dir)
  (let* ((key #(1 2 3 4 5 6 7 8))
         (iv #(0 0 0 0 0 0 0 0))
         (input-path "generated-files/test-input-cfb1-multiline.txt")
         (encrypted-path "generated-files/test-encrypted-cfb1-multiline.bin")
         (decrypted-path "generated-files/test-decrypted-cfb1-multiline.txt")
         (lines '("Hello File CFB1 World!"
                  "This is line two."
                  "Third line with symbols: @#$%^&*()"
                  "日本語の行もテストします。")))
    ;; Write multi-line input file
    (with-open-file (out input-path :direction :output :if-exists :supersede :if-does-not-exist :create)
      (dolist (line lines)
        (write-line line out)))

    ;; Encrypt and decrypt
    (des-api::encrypt-file-cfb1 input-path encrypted-path key iv)
    (des-api::decrypt-file-cfb1 encrypted-path decrypted-path key iv)

    ;; Compare contents line-by-line
    (with-open-file (in decrypted-path :direction :input)
      (loop for expected in lines
            for actual = (read-line in nil)
            always (string= expected actual)))))

(defun test-file-ofb-roundtrip ()
  (ensure-generated-files-dir)
  (let* ((key #(1 2 3 4 5 6 7 8))
         (iv #(0 0 0 0 0 0 0 0))
         (input-path "generated-files/test-input-ofb.txt")
         (encrypted-path "generated-files/test-encrypted-ofb.bin")
         (decrypted-path "generated-files/test-decrypted-ofb.txt"))
    ;; Write test file
    (with-open-file (out input-path :direction :output :if-exists :supersede :if-does-not-exist :create)
      (write-line "Hello File OFB World!" out))
    ;; Encrypt and decrypt
    (des-api::encrypt-file-ofb input-path encrypted-path key iv)
    (des-api::decrypt-file-ofb encrypted-path decrypted-path key iv)
    ;; Compare contents
    (with-open-file (in decrypted-path :direction :input)
      (let ((line (read-line in)))
        (format t "Decrypted file content: ~A~%" line)
        (string= line "Hello File OFB World!")))))

(defun test-file-ofb-roundtrip-multiline ()
  (ensure-generated-files-dir)
  (let* ((key #(1 2 3 4 5 6 7 8))
         (iv #(0 0 0 0 0 0 0 0))
         (input-path "generated-files/test-input-ofb-multiline.txt")
         (encrypted-path "generated-files/test-encrypted-ofb-multiline.bin")
         (decrypted-path "generated-files/test-decrypted-ofb-multiline.txt")
         (lines '("Hello File OFB World!"
                  "This is line two."
                  "Third line with symbols: @#$%^&*()"
                  "日本語の行もテストします。")))
    ;; Write multi-line input file
    (with-open-file (out input-path :direction :output :if-exists :supersede :if-does-not-exist :create)
      (dolist (line lines)
        (write-line line out)))

    ;; Encrypt and decrypt
    (des-api::encrypt-file-ofb input-path encrypted-path key iv)
    (des-api::decrypt-file-ofb encrypted-path decrypted-path key iv)

    ;; Compare contents line-by-line
    (with-open-file (in decrypted-path :direction :input)
      (loop for expected in lines
            for actual = (read-line in nil)
            always (string= expected actual)))))

(defun test-file-ctr-roundtrip ()
  (ensure-generated-files-dir)
  (let* ((key #(1 2 3 4 5 6 7 8))
         (iv #(0 0 0 0 0 0 0 0))
         (input-path "generated-files/test-input-ctr.txt")
         (encrypted-path "generated-files/test-encrypted-ctr.bin")
         (decrypted-path "generated-files/test-decrypted-ctr.txt"))
    ;; Write test file
    (with-open-file (out input-path :direction :output :if-exists :supersede :if-does-not-exist :create)
      (write-line "Hello File CTR World!" out))
    ;; Encrypt and decrypt
    (des-api::encrypt-file-ctr input-path encrypted-path key iv)
    (des-api::decrypt-file-ctr encrypted-path decrypted-path key iv)
    ;; Compare contents
    (with-open-file (in decrypted-path :direction :input)
      (let ((line (read-line in)))
        (format t "Decrypted file content: ~A~%" line)
        (string= line "Hello File CTR World!")))))

(defun test-file-ctr-roundtrip-multiline ()
  (ensure-generated-files-dir)
  (let* ((key #(1 2 3 4 5 6 7 8))
         (iv #(0 0 0 0 0 0 0 0))
         (input-path "generated-files/test-input-ctr-multiline.txt")
         (encrypted-path "generated-files/test-encrypted-ctr-multiline.bin")
         (decrypted-path "generated-files/test-decrypted-ctr-multiline.txt")
         (lines '("Hello File CTR World!"
                  "This is line two."
                  "Third line with symbols: @#$%^&*()"
                  "日本語の行もテストします。")))
    ;; Write multi-line input file
    (with-open-file (out input-path :direction :output :if-exists :supersede :if-does-not-exist :create)
      (dolist (line lines)
        (write-line line out)))

    ;; Encrypt and decrypt
    (des-api::encrypt-file-ctr input-path encrypted-path key iv)
    (des-api::decrypt-file-ctr encrypted-path decrypted-path key iv)

    ;; Compare contents line-by-line
    (with-open-file (in decrypted-path :direction :input)
      (loop for expected in lines
            for actual = (read-line in nil)
            always (string= expected actual)))))

(defun test-file-base64-ecb-roundtrip ()
  (ensure-generated-files-dir)
  (let* ((key #(1 2 3 4 5 6 7 8))
         (input-path "generated-files/test-input-base64-ecb.txt")
         (encrypted-path "generated-files/test-encrypted-base64-ecb.bin")
         (decrypted-path "generated-files/test-decrypted-base64-ecb.txt"))
    ;; Write single-line file
    (with-open-file (out input-path :direction :output :if-exists :supersede :if-does-not-exist :create)
      (write-line "Hello File Base64 ECB World!" out))

    ;; Encrypt and decrypt
    (des-api::encrypt-base64-file-ecb input-path encrypted-path key)
    (des-api::decrypt-base64-file-ecb encrypted-path decrypted-path key)

    ;; Compare contents
    (with-open-file (in decrypted-path :direction :input)
      (let ((line (read-line in)))
        (format t "Decrypted file content: ~A~%" line)
        (string= line "Hello File Base64 ECB World!")))))

(defun test-file-base64-ecb-roundtrip-multiline ()
  (ensure-generated-files-dir)
  (let* ((key #(1 2 3 4 5 6 7 8))
         (input-path "generated-files/test-input-base64-ecb-multiline.txt")
         (encrypted-path "generated-files/test-encrypted-base64-ecb-multiline.bin")
         (decrypted-path "generated-files/test-decrypted-base64-ecb-multiline.txt")
         (lines '("Hello File Base64 ECB World!"
                  "This is line two."
                  "And here’s line three — with punctuation!"
                  "最後の行は日本語です。")))
    ;; Write multi-line input file
    (with-open-file (out input-path :direction :output :if-exists :supersede :if-does-not-exist :create)
      (dolist (line lines)
        (write-line line out)))

    ;; Encrypt and decrypt
    (des-api::encrypt-base64-file-ecb input-path encrypted-path key)
    (des-api::decrypt-base64-file-ecb encrypted-path decrypted-path key)

    ;; Compare contents line-by-line
    (with-open-file (in decrypted-path :direction :input)
      (loop for expected in lines
            for actual = (read-line in nil)
            always (string= expected actual)))))

(defun test-file-base64-cbc-roundtrip ()
  (ensure-generated-files-dir)
  (let* ((key #(1 2 3 4 5 6 7 8))
         (iv #(0 0 0 0 0 0 0 0))
         (input-path "generated-files/test-input-base64-cbc.txt")
         (encrypted-path "generated-files/test-encrypted-base64-cbc.bin")
         (decrypted-path "generated-files/test-decrypted-base64-cbc.txt"))
    ;; Write test file
    (with-open-file (out input-path :direction :output :if-exists :supersede :if-does-not-exist :create)
      (write-line "Hello File CBC/Base64 World!" out))
    ;; Encrypt and decrypt
    (des-api::encrypt-base64-file-cbc input-path encrypted-path key iv)
    (des-api::decrypt-base64-file-cbc encrypted-path decrypted-path key iv)
    ;; Compare contents
    (with-open-file (in decrypted-path :direction :input)
      (let ((line (read-line in)))
        (format t "Decrypted file content: ~A~%" line)
        (string= line "Hello File CBC/Base64 World!")))))

(defun test-file-base64-cbc-roundtrip-multiline ()
  (ensure-generated-files-dir)
  (let* ((key #(1 2 3 4 5 6 7 8))
         (iv #(0 0 0 0 0 0 0 0))
         (input-path "generated-files/test-input-base64-multiline-cbc.txt")
         (encrypted-path "generated-files/test-encrypted-base64-multiline-cbc.bin")
         (decrypted-path "generated-files/test-decrypted-base64-multiline-cbc.txt")
         (lines '("Hello File CBC/Base64 World!"
                  "This is line two."
                  "And here’s line three — with punctuation!"
                  "最後の行は日本語です。")))
    ;; Write multi-line test file
    (with-open-file (out input-path :direction :output :if-exists :supersede :if-does-not-exist :create)
      (dolist (line lines)
        (write-line line out)))

    ;; Encrypt and decrypt
    (des-api::encrypt-base64-file-cbc input-path encrypted-path key iv)
    (des-api::decrypt-base64-file-cbc encrypted-path decrypted-path key iv)

    ;; Compare contents line-by-line
    (with-open-file (in decrypted-path :direction :input)
      (loop for expected in lines
            for actual = (read-line in nil)
            always (string= expected actual)))))

(defun test-file-base64-cfb-roundtrip ()
  (ensure-generated-files-dir)
  (let* ((key #(1 2 3 4 5 6 7 8))
         (iv #(0 0 0 0 0 0 0 0))
         (input-path "generated-files/test-input-base64-cfb.txt")
         (encrypted-path "generated-files/test-encrypted-base64-cfb.bin")
         (decrypted-path "generated-files/test-decrypted-base64-cfb.txt"))
    ;; Write test file
    (with-open-file (out input-path :direction :output :if-exists :supersede :if-does-not-exist :create)
      (write-line "Hello File CFB/Base64 World!" out))
    ;; Encrypt and decrypt
    (des-api::encrypt-base64-file-cfb input-path encrypted-path key iv)
    (des-api::decrypt-base64-file-cfb encrypted-path decrypted-path key iv)
    ;; Compare contents
    (with-open-file (in decrypted-path :direction :input)
      (let ((line (read-line in)))
        (format t "Decrypted file content: ~A~%" line)
        (string= line "Hello File CFB/Base64 World!")))))

(defun test-file-base64-cfb-roundtrip-multiline ()
  (ensure-generated-files-dir)
  (let* ((key #(1 2 3 4 5 6 7 8))
         (iv #(0 0 0 0 0 0 0 0))
         (input-path "generated-files/test-input-base64-multiline-cfb.txt")
         (encrypted-path "generated-files/test-encrypted-base64-multiline-cfb.bin")
         (decrypted-path "generated-files/test-decrypted-base64-multiline-cfb.txt")
         (lines '("Hello File CFB/Base64 World!"
                  "This is line two."
                  "And here’s line three — with punctuation!"
                  "最後の行は日本語です。")))
    ;; Write multi-line test file
    (with-open-file (out input-path :direction :output :if-exists :supersede :if-does-not-exist :create)
      (dolist (line lines)
        (write-line line out)))

    ;; Encrypt and decrypt
    (des-api::encrypt-base64-file-cfb input-path encrypted-path key iv)
    (des-api::decrypt-base64-file-cfb encrypted-path decrypted-path key iv)

    ;; Compare contents line-by-line
    (with-open-file (in decrypted-path :direction :input)
      (loop for expected in lines
            for actual = (read-line in nil)
            always (string= expected actual)))))

(defun test-file-base64-cfb8-roundtrip ()
  (ensure-generated-files-dir)
  (let* ((key #(1 2 3 4 5 6 7 8))
         (iv #(0 0 0 0 0 0 0 0))
         (input-path "generated-files/test-input-base64-cfb8.txt")
         (encrypted-path "generated-files/test-encrypted-base64-cfb8.bin")
         (decrypted-path "generated-files/test-decrypted-base64-cfb8.txt"))
    ;; Write test file
    (with-open-file (out input-path :direction :output :if-exists :supersede :if-does-not-exist :create)
      (write-line "Hello File CFB8/Base64 World!" out))
    ;; Encrypt and decrypt
    (des-api::encrypt-base64-file-cfb8 input-path encrypted-path key iv)
    (des-api::decrypt-base64-file-cfb8 encrypted-path decrypted-path key iv)
    ;; Compare contents
    (with-open-file (in decrypted-path :direction :input)
      (let ((line (read-line in)))
        (format t "Decrypted file content: ~A~%" line)
        (string= line "Hello File CFB8/Base64 World!")))))

(defun test-file-base64-cfb8-roundtrip-multiline ()
  (ensure-generated-files-dir)
  (let* ((key #(1 2 3 4 5 6 7 8))
         (iv #(0 0 0 0 0 0 0 0))
         (input-path "generated-files/test-input-base64-multiline-cfb8.txt")
         (encrypted-path "generated-files/test-encrypted-base64-multiline-cfb8.bin")
         (decrypted-path "generated-files/test-decrypted-base64-multiline-cfb8.txt")
         (lines '("Hello File CFB8/Base64 World!"
                  "This is line two."
                  "And here’s line three — with punctuation!"
                  "最後の行は日本語です。")))
    ;; Write multi-line test file
    (with-open-file (out input-path :direction :output :if-exists :supersede :if-does-not-exist :create)
      (dolist (line lines)
        (write-line line out)))

    ;; Encrypt and decrypt
    (des-api::encrypt-base64-file-cfb8 input-path encrypted-path key iv)
    (des-api::decrypt-base64-file-cfb8 encrypted-path decrypted-path key iv)

    ;; Compare contents line-by-line
    (with-open-file (in decrypted-path :direction :input)
      (loop for expected in lines
            for actual = (read-line in nil)
            always (string= expected actual)))))

(defun test-file-base64-cfb1-roundtrip ()
  (ensure-generated-files-dir)
  (let* ((key #(1 2 3 4 5 6 7 8))
         (iv #(0 0 0 0 0 0 0 0))
         (input-path "generated-files/test-input-base64-cfb1.txt")
         (encrypted-path "generated-files/test-encrypted-base64-cfb1.bin")
         (decrypted-path "generated-files/test-decrypted-base64-cfb1.txt"))
    ;; Write test file
    (with-open-file (out input-path :direction :output :if-exists :supersede :if-does-not-exist :create)
      (write-line "Hello File CFB1/Base64 World!" out))
    ;; Encrypt and decrypt
    (des-api::encrypt-base64-file-cfb1 input-path encrypted-path key iv)
    (des-api::decrypt-base64-file-cfb1 encrypted-path decrypted-path key iv)
    ;; Compare contents
    (with-open-file (in decrypted-path :direction :input)
      (let ((line (read-line in)))
        (format t "Decrypted file content: ~A~%" line)
        (string= line "Hello File CFB1/Base64 World!")))))

(defun test-file-base64-cfb1-roundtrip-multiline ()
  (ensure-generated-files-dir)
  (let* ((key #(1 2 3 4 5 6 7 8))
         (iv #(0 0 0 0 0 0 0 0))
         (input-path "generated-files/test-input-base64-multiline-cfb1.txt")
         (encrypted-path "generated-files/test-encrypted-base64-multiline-cfb1.bin")
         (decrypted-path "generated-files/test-decrypted-base64-multiline-cfb1.txt")
         (lines '("Hello File CFB1/Base64 World!"
                  "This is line two."
                  "And here’s line three — with punctuation!"
                  "最後の行は日本語です。")))
    ;; Write multi-line test file
    (with-open-file (out input-path :direction :output :if-exists :supersede :if-does-not-exist :create)
      (dolist (line lines)
        (write-line line out)))

    ;; Encrypt and decrypt
    (des-api::encrypt-base64-file-cfb1 input-path encrypted-path key iv)
    (des-api::decrypt-base64-file-cfb1 encrypted-path decrypted-path key iv)

    ;; Compare contents line-by-line
    (with-open-file (in decrypted-path :direction :input)
      (loop for expected in lines
            for actual = (read-line in nil)
            always (string= expected actual)))))

(defun test-file-base64-ofb-roundtrip ()
  (ensure-generated-files-dir)
  (let* ((key #(1 2 3 4 5 6 7 8))
         (iv #(0 0 0 0 0 0 0 0))
         (input-path "generated-files/test-input-base64-ofb.txt")
         (encrypted-path "generated-files/test-encrypted-base64-ofb.bin")
         (decrypted-path "generated-files/test-decrypted-base64-ofb.txt"))
    ;; Write test file
    (with-open-file (out input-path :direction :output :if-exists :supersede :if-does-not-exist :create)
      (write-line "Hello File OFB/Base64 World!" out))
    ;; Encrypt and decrypt
    (des-api::encrypt-base64-file-ofb input-path encrypted-path key iv)
    (des-api::decrypt-base64-file-ofb encrypted-path decrypted-path key iv)
    ;; Compare contents
    (with-open-file (in decrypted-path :direction :input)
      (let ((line (read-line in)))
        (format t "Decrypted file content: ~A~%" line)
        (string= line "Hello File OFB/Base64 World!")))))

(defun test-file-base64-ofb-roundtrip-multiline ()
  (ensure-generated-files-dir)
  (let* ((key #(1 2 3 4 5 6 7 8))
         (iv #(0 0 0 0 0 0 0 0))
         (input-path "generated-files/test-input-base64-multiline-ofb.txt")
         (encrypted-path "generated-files/test-encrypted-base64-multiline-ofb.bin")
         (decrypted-path "generated-files/test-decrypted-base64-multiline-ofb.txt")
         (lines '("Hello File OFB/Base64 World!"
                  "This is line two."
                  "And here’s line three — with punctuation!"
                  "最後の行は日本語です。")))
    ;; Write multi-line test file
    (with-open-file (out input-path :direction :output :if-exists :supersede :if-does-not-exist :create)
      (dolist (line lines)
        (write-line line out)))

    ;; Encrypt and decrypt
    (des-api::encrypt-base64-file-ofb input-path encrypted-path key iv)
    (des-api::decrypt-base64-file-ofb encrypted-path decrypted-path key iv)

    ;; Compare contents line-by-line
    (with-open-file (in decrypted-path :direction :input)
      (loop for expected in lines
            for actual = (read-line in nil)
            always (string= expected actual)))))

(defun test-file-base64-ctr-roundtrip ()
  (ensure-generated-files-dir)
  (let* ((key #(1 2 3 4 5 6 7 8))
         (iv #(0 0 0 0 0 0 0 0))
         (input-path "generated-files/test-input-base64-ctr.txt")
         (encrypted-path "generated-files/test-encrypted-base64-ctr.bin")
         (decrypted-path "generated-files/test-decrypted-base64-ctr.txt"))
    ;; Write test file
    (with-open-file (out input-path :direction :output :if-exists :supersede :if-does-not-exist :create)
      (write-line "Hello File CTR/Base64 World!" out))
    ;; Encrypt and decrypt
    (des-api::encrypt-base64-file-ctr input-path encrypted-path key iv)
    (des-api::decrypt-base64-file-ctr encrypted-path decrypted-path key iv)
    ;; Compare contents
    (with-open-file (in decrypted-path :direction :input)
      (let ((line (read-line in)))
        (format t "Decrypted file content: ~A~%" line)
        (string= line "Hello File CTR/Base64 World!")))))

(defun test-file-base64-ctr-roundtrip-multiline ()
  (ensure-generated-files-dir)
  (let* ((key #(1 2 3 4 5 6 7 8))
         (iv #(0 0 0 0 0 0 0 0))
         (input-path "generated-files/test-input-base64-multiline-ctr.txt")
         (encrypted-path "generated-files/test-encrypted-base64-multiline-ctr.bin")
         (decrypted-path "generated-files/test-decrypted-base64-multiline-ctr.txt")
         (lines '("Hello File CTR/Base64 World!"
                  "This is line two."
                  "And here’s line three — with punctuation!"
                  "最後の行は日本語です。")))
    ;; Write multi-line test file
    (with-open-file (out input-path :direction :output :if-exists :supersede :if-does-not-exist :create)
      (dolist (line lines)
        (write-line line out)))

    ;; Encrypt and decrypt
    (des-api::encrypt-base64-file-ctr input-path encrypted-path key iv)
    (des-api::decrypt-base64-file-ctr encrypted-path decrypted-path key iv)

    ;; Compare contents line-by-line
    (with-open-file (in decrypted-path :direction :input)
      (loop for expected in lines
            for actual = (read-line in nil)
            always (string= expected actual)))))
