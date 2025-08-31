(defpackage :tls-aes-rsp128-parser
  (:use :cl :parse-utils :shared-utils :tls-aes-utils :tls-aes128 :tls-aes-ghash :tls-aes128-gcm :tls-aes128-mac)
  (:export :parse-ecb128-rsp :parse-ecb128-rsp-decrypt :parse-cbc128-rsp :parse-cbc128-rsp-decrypt
	   :parse-ctr128-rsp :parse-ctr128-rsp-decrypt :parse-ofb128-rsp :parse-ofb128-rsp-decrypt
	   :parse-cfb128-rsp :parse-cfb128-rsp-decrypt
	   :parse128-cfb8-rsp :parse128-cfb8-rsp-decrypt
	   :parse128-cfb1-rsp :parse128-cfb1-rsp-decrypt
	   :parse128-gcm-rsp :parse128-gcm-rsp-decrypt
	   :parse-aes128-cmac-rsp :parse-aes128-cmac-rsp-verify))

(in-package :tls-aes-rsp128-parser)

(defun parse-ecb128-rsp (filename &optional verbose)
  "Parses a NIST ECB128 .rsp file and returns a list of test cases."
  (with-open-file (stream filename)
    (let ((cases '())
          (current-case (make-hash-table :test 'equal))
          (mode :skip))
      (loop for line = (read-line stream nil)
            while line do
            (cond
              ((starts-with "[" line)
               (setf mode (if (string= line "[ENCRYPT]") :encrypt :skip)))
              ((string= line "") nil) ; skip blank lines
              ((eq mode :encrypt)
               (cond
                 ((starts-with "COUNT = " line)
                  (setf (gethash "COUNT" current-case)
                        (parse-integer (subseq line 8))))
                 ((starts-with "KEY = " line)
                  (setf (gethash "KEY" current-case)
                        (hex-string-to-byte-vector (subseq line 6))))
                 ((starts-with "PLAINTEXT = " line)
                  (setf (gethash "PLAINTEXT" current-case)
                        (hex-string-to-byte-vector (subseq line 12))))
                 ((starts-with "CIPHERTEXT = " line)
                  (progn
                    (setf (gethash "CIPHERTEXT" current-case)
                          (hex-string-to-byte-vector (subseq line 12)))
		    (when verbose
			(format t "~%Parsed ECB128 test case ~D" (gethash "COUNT" current-case)))
                    (push current-case cases)
                    (setf current-case (make-hash-table :test 'equal))))))))
      (nreverse cases))))

(defun parse-ecb128-rsp-decrypt (filename &optional verbose)
  "Parses a NIST ECB128 .rsp file and returns a list of test cases."
  (with-open-file (stream filename)
    (let ((cases '())
          (current-case (make-hash-table :test 'equal))
          (mode :skip))
      (loop for line = (read-line stream nil)
            while line do
            (cond
              ((starts-with "[" line)
               (setf mode (if (string= line "[DECRYPT]") :decrypt :skip)))
              ((string= line "") nil) ; skip blank lines
              ((eq mode :decrypt)
               (cond
                 ((starts-with "COUNT = " line)
                  (setf (gethash "COUNT" current-case)
                        (parse-integer (subseq line 8))))
                 ((starts-with "KEY = " line)
                  (setf (gethash "KEY" current-case)
                        (hex-string-to-byte-vector (subseq line 6))))
                 ((starts-with "CIPHERTEXT = " line)
                  (setf (gethash "CIPHERTEXT" current-case)
                        (hex-string-to-byte-vector (subseq line 12))))
                 ((starts-with "PLAINTEXT = " line)
                  (progn
                    (setf (gethash "PLAINTEXT" current-case)
                          (hex-string-to-byte-vector (subseq line 12)))
		    (when verbose
			(format t "~%Parsed ECB128 DECRYPT test case ~D" (gethash "COUNT" current-case)))
                    (push current-case cases)
                    (setf current-case (make-hash-table :test 'equal))))))))
      (nreverse cases))))

(defun parse-cbc128-rsp (filename &optional verbose)
  "Parses a NIST CBC128 .rsp file and returns a list of ENCRYPT test cases."
  (with-open-file (stream filename)
    (let ((cases '())
          (current-case (make-hash-table :test 'equal))
          (mode :skip))
      (loop for line = (read-line stream nil)
            while line do
            (cond
              ((starts-with "[" line)
               (cond
                 ((string= line "[ENCRYPT]") (setf mode :encrypt))
                 ((string= line "[DECRYPT]") (setf mode :skip))))
              ((string= line "") nil) ; skip blank lines
              ((eq mode :encrypt)
               (cond
                 ((starts-with "COUNT = " line)
                  (setf (gethash "COUNT" current-case)
                        (parse-integer (subseq line 8))))
                 ((starts-with "KEY = " line)
                  (setf (gethash "KEY" current-case)
                        (hex-string-to-byte-vector (subseq line 6))))
                 ((starts-with "IV = " line)
                  (setf (gethash "IV" current-case)
                        (hex-string-to-byte-vector (subseq line 5))))
                 ((starts-with "PLAINTEXT = " line)
                  (setf (gethash "PLAINTEXT" current-case)
                        (hex-string-to-byte-vector (subseq line 11))))
                 ((starts-with "CIPHERTEXT = " line)
                  (setf (gethash "CIPHERTEXT" current-case)
                        (hex-string-to-byte-vector (subseq line 12)))
		  (when verbose
                      (format t "~%Parsed CBC128 test case ~D" (gethash "COUNT" current-case)))
                  (push current-case cases)
                  (setf current-case (make-hash-table :test 'equal)))))))
      (nreverse cases))))

(defun parse-cbc128-rsp-decrypt (filename &optional verbose)
  "Parses a NIST CBC128 .rsp file and returns a list of DECRYPT test cases."
  (with-open-file (stream filename)
    (let ((cases '())
          (current-case (make-hash-table :test 'equal))
          (mode :skip))
      (loop for line = (read-line stream nil)
            while line do
            (cond
              ((starts-with "[" line)
               (cond
                 ((string= line "[DECRYPT]") (setf mode :decrypt))
                 ((string= line "[ENCRYPT]") (setf mode :skip))))
              ((string= line "") nil) ; skip blank lines
              ((eq mode :decrypt)
               (cond
                 ((starts-with "COUNT = " line)
                  (setf (gethash "COUNT" current-case)
                        (parse-integer (subseq line 8))))
                 ((starts-with "KEY = " line)
                  (setf (gethash "KEY" current-case)
                        (hex-string-to-byte-vector (subseq line 6))))
                 ((starts-with "IV = " line)
                  (setf (gethash "IV" current-case)
                        (hex-string-to-byte-vector (subseq line 5))))
                 ((starts-with "CIPHERTEXT = " line)
                  (setf (gethash "CIPHERTEXT" current-case)
                        (hex-string-to-byte-vector (subseq line 12))))
                 ((starts-with "PLAINTEXT = " line)
                  (setf (gethash "PLAINTEXT" current-case)
                        (hex-string-to-byte-vector (subseq line 11)))
		  (when verbose
                      (format t "~%Parsed CBC128 decrypt test case ~D" (gethash "COUNT" current-case)))
                  (push current-case cases)
                  (setf current-case (make-hash-table :test 'equal)))))))
      (nreverse cases))))

(defun parse-ctr128-rsp (filename &optional verbose)
  "Parses a NIST CTR128 .rsp file and returns a list of ENCRYPT test cases."
  (with-open-file (stream filename)
    (let ((cases '())
          (current-case (make-hash-table :test 'equal))
          (mode :skip))
      (loop for line = (read-line stream nil)
            while line do
            (cond
              ((starts-with "[" line)
               (cond
                 ((string= line "[ENCRYPT]") (setf mode :encrypt))
                 ((string= line "[DECRYPT]") (setf mode :skip))))
              ((string= line "") nil)
              ((eq mode :encrypt)
               (cond
                 ((starts-with "COUNT = " line)
                  (setf (gethash "COUNT" current-case)
                        (parse-integer (subseq line 8))))
                 ((starts-with "KEY = " line)
                  (setf (gethash "KEY" current-case)
                        (hex-string-to-byte-vector (subseq line 6))))
                 ((starts-with "IV = " line)
                  (setf (gethash "IV" current-case)
                        (hex-string-to-byte-vector (subseq line 5))))
                 ((starts-with "PLAINTEXT = " line)
                  (setf (gethash "PLAINTEXT" current-case)
                        (hex-string-to-byte-vector (subseq line 11))))
                 ((starts-with "CIPHERTEXT = " line)
                  (setf (gethash "CIPHERTEXT" current-case)
                        (hex-string-to-byte-vector (subseq line 12)))
		  (when verbose
                      (format t "~%Parsed CTR128 test case ~D" (gethash "COUNT" current-case)))
                  (push current-case cases)
                  (setf current-case (make-hash-table :test 'equal)))))))
      (nreverse cases))))

(defun parse-ctr128-rsp-decrypt (filename &optional verbose)
  "Parses a NIST CTR128 .rsp file and returns a list of DECRYPT test cases."
  (with-open-file (stream filename)
    (let ((cases '())
          (current-case (make-hash-table :test 'equal))
          (mode :skip))
      (loop for line = (read-line stream nil)
            while line do
            (cond
              ((starts-with "[" line)
               (cond
                 ((string= line "[DECRYPT]") (setf mode :decrypt))
                 ((string= line "[ENCRYPT]") (setf mode :skip))))
              ((string= line "") nil)
              ((eq mode :decrypt)
               (cond
                 ((starts-with "COUNT = " line)
                  (setf (gethash "COUNT" current-case)
                        (parse-integer (subseq line 8))))
                 ((starts-with "KEY = " line)
                  (setf (gethash "KEY" current-case)
                        (hex-string-to-byte-vector (subseq line 6))))
                 ((starts-with "IV = " line)
                  (setf (gethash "IV" current-case)
                        (hex-string-to-byte-vector (subseq line 5))))
                 ((starts-with "CIPHERTEXT = " line)
                  (setf (gethash "CIPHERTEXT" current-case)
                        (hex-string-to-byte-vector (subseq line 12))))
                 ((starts-with "PLAINTEXT = " line)
                  (setf (gethash "PLAINTEXT" current-case)
                        (hex-string-to-byte-vector (subseq line 11)))
		  (when verbose
                      (format t "~%Parsed CTR128 test case ~D" (gethash "COUNT" current-case)))
                  (push current-case cases)
                  (setf current-case (make-hash-table :test 'equal)))))))
      (nreverse cases))))

(defun parse-ofb128-rsp (filename &optional verbose)
  "Parses a NIST OFB128 .rsp file and returns a list of ENCRYPT test cases."
  (with-open-file (stream filename)
    (let ((cases '())
          (current-case (make-hash-table :test 'equal))
          (mode :skip))
      (loop for line = (read-line stream nil)
            while line do
            (cond
              ((starts-with "[" line)
               (cond
                 ((string= line "[ENCRYPT]") (setf mode :encrypt))
                 ((string= line "[DECRYPT]") (setf mode :skip))))
              ((string= line "") nil)
              ((eq mode :encrypt)
               (cond
                 ((starts-with "COUNT = " line)
                  (setf (gethash "COUNT" current-case)
                        (parse-integer (subseq line 8))))
                 ((starts-with "KEY = " line)
                  (setf (gethash "KEY" current-case)
                        (hex-string-to-byte-vector (subseq line 6))))
                 ((starts-with "IV = " line)
                  (setf (gethash "IV" current-case)
                        (hex-string-to-byte-vector (subseq line 5))))
                 ((starts-with "PLAINTEXT = " line)
                  (setf (gethash "PLAINTEXT" current-case)
                        (hex-string-to-byte-vector (subseq line 11))))
                 ((starts-with "CIPHERTEXT = " line)
                  (setf (gethash "CIPHERTEXT" current-case)
                        (hex-string-to-byte-vector (subseq line 12)))
		  (when verbose
                      (format t "~%Parsed OFB128 test case ~D" (gethash "COUNT" current-case)))
                  (push current-case cases)
                  (setf current-case (make-hash-table :test 'equal)))))))
      (nreverse cases))))

(defun parse-ofb128-rsp-decrypt (filename &optional verbose)
  "Parses a NIST OFB128 .rsp file and returns a list of DECRYPT test cases."
  (with-open-file (stream filename)
    (let ((cases '())
          (current-case (make-hash-table :test 'equal))
          (mode :skip))
      (loop for line = (read-line stream nil)
            while line do
            (cond
              ((starts-with "[" line)
               (cond
                 ((string= line "[DECRYPT]") (setf mode :decrypt))
                 ((string= line "[ENCRYPT]") (setf mode :skip))))
              ((string= line "") nil)
              ((eq mode :decrypt)
               (cond
                 ((starts-with "COUNT = " line)
                  (setf (gethash "COUNT" current-case)
                        (parse-integer (subseq line 8))))
                 ((starts-with "KEY = " line)
                  (setf (gethash "KEY" current-case)
                        (hex-string-to-byte-vector (subseq line 6))))
                 ((starts-with "IV = " line)
                  (setf (gethash "IV" current-case)
                        (hex-string-to-byte-vector (subseq line 5))))
                 ((starts-with "CIPHERTEXT = " line)
                  (setf (gethash "CIPHERTEXT" current-case)
                        (hex-string-to-byte-vector (subseq line 12))))
                 ((starts-with "PLAINTEXT = " line)
                  (setf (gethash "PLAINTEXT" current-case)
                        (hex-string-to-byte-vector (subseq line 11)))
		  (when verbose
                      (format t "~%Parsed OFB128 test case ~D" (gethash "COUNT" current-case)))
                  (push current-case cases)
                  (setf current-case (make-hash-table :test 'equal)))))))
      (nreverse cases))))

(defun parse-cfb128-rsp (filename &optional verbose)
  "Parses a NIST CFB128 .rsp file and returns a list of ENCRYPT test cases."
  (with-open-file (stream filename)
    (let ((cases '())
          (current-case (make-hash-table :test 'equal))
          (mode :skip))
      (loop for line = (read-line stream nil)
            while line do
            (cond
              ((starts-with "[" line)
               (cond
                 ((string= line "[ENCRYPT]") (setf mode :encrypt))
                 ((string= line "[DECRYPT]") (setf mode :skip))))
              ((string= line "") nil)
              ((eq mode :encrypt)
               (cond
                 ((starts-with "COUNT = " line)
                  (setf (gethash "COUNT" current-case)
                        (parse-integer (subseq line 8))))
                 ((starts-with "KEY = " line)
                  (setf (gethash "KEY" current-case)
                        (hex-string-to-byte-vector (subseq line 6))))
                 ((starts-with "IV = " line)
                  (setf (gethash "IV" current-case)
                        (hex-string-to-byte-vector (subseq line 5))))
                 ((starts-with "PLAINTEXT = " line)
                  (setf (gethash "PLAINTEXT" current-case)
                        (hex-string-to-byte-vector (subseq line 11))))
                 ((starts-with "CIPHERTEXT = " line)
                  (setf (gethash "CIPHERTEXT" current-case)
                        (hex-string-to-byte-vector (subseq line 12)))
		  (when verbose
                      (format t "~%Parsed CFB128 test case ~D" (gethash "COUNT" current-case)))
                  (push current-case cases)
                  (setf current-case (make-hash-table :test 'equal)))))))
      (nreverse cases))))

(defun parse-cfb128-rsp-decrypt (filename &optional verbose)
  "Parses a NIST CFB128 .rsp file and returns a list of DECRYPT test cases."
  (with-open-file (stream filename)
    (let ((cases '())
          (current-case (make-hash-table :test 'equal))
          (mode :skip))
      (loop for line = (read-line stream nil)
            while line do
            (cond
              ((starts-with "[" line)
               (cond
                 ((string= line "[DECRYPT]") (setf mode :decrypt))
                 ((string= line "[ENCRYPT]") (setf mode :skip))))
              ((string= line "") nil)
              ((eq mode :decrypt)
               (cond
                 ((starts-with "COUNT = " line)
                  (setf (gethash "COUNT" current-case)
                        (parse-integer (subseq line 8))))
                 ((starts-with "KEY = " line)
                  (setf (gethash "KEY" current-case)
                        (hex-string-to-byte-vector (subseq line 6))))
                 ((starts-with "IV = " line)
                  (setf (gethash "IV" current-case)
                        (hex-string-to-byte-vector (subseq line 5))))
                 ((starts-with "CIPHERTEXT = " line)
                  (setf (gethash "CIPHERTEXT" current-case)
                        (hex-string-to-byte-vector (subseq line 12))))
                 ((starts-with "PLAINTEXT = " line)
                  (setf (gethash "PLAINTEXT" current-case)
                        (hex-string-to-byte-vector (subseq line 11)))
		  (when verbose
                      (format t "~%Parsed CFB128 test case ~D" (gethash "COUNT" current-case)))
                  (push current-case cases)
                  (setf current-case (make-hash-table :test 'equal)))))))
      (nreverse cases))))

(defun parse128-cfb8-rsp (filename &optional verbose)
  "Parses a NIST CFB8 .rsp file and returns a list of ENCRYPT test cases."
  (with-open-file (stream filename)
    (let ((cases '())
          (current-case (make-hash-table :test 'equal))
          (mode :skip))
      (loop for line = (read-line stream nil)
            while line do
            (cond
              ((starts-with "[" line)
               (cond
                 ((string= line "[ENCRYPT]") (setf mode :encrypt))
                 ((string= line "[DECRYPT]") (setf mode :skip))))
              ((string= line "") nil)
              ((eq mode :encrypt)
               (cond
                 ((starts-with "COUNT = " line)
                  (setf (gethash "COUNT" current-case)
                        (parse-integer (subseq line 8))))
                 ((starts-with "KEY = " line)
                  (setf (gethash "KEY" current-case)
                        (hex-string-to-byte-vector (subseq line 6))))
                 ((starts-with "IV = " line)
                  (setf (gethash "IV" current-case)
                        (hex-string-to-byte-vector (subseq line 5))))
                 ((starts-with "PLAINTEXT = " line)
                  (setf (gethash "PLAINTEXT" current-case)
                        (hex-string-to-byte-vector (subseq line 11))))
                 ((starts-with "CIPHERTEXT = " line)
                  (setf (gethash "CIPHERTEXT" current-case)
                        (hex-string-to-byte-vector (subseq line 12)))
		  (when verbose
                    (format t "~%Parsed CFB8 test case ~D" (gethash "COUNT" current-case)))
                  (push current-case cases)
                  (setf current-case (make-hash-table :test 'equal)))))))
      (nreverse cases))))

(defun parse128-cfb8-rsp-decrypt (filename &optional verbose)
  "Parses a NIST CFB8 .rsp file and returns a list of DECRYPT test cases."
  (with-open-file (stream filename)
    (let ((cases '())
          (current-case (make-hash-table :test 'equal))
          (mode :skip))
      (loop for line = (read-line stream nil)
            while line do
            (cond
              ((starts-with "[" line)
               (cond
                 ((string= line "[DECRYPT]") (setf mode :decrypt))
                 ((string= line "[ENCRYPT]") (setf mode :skip))))
              ((string= line "") nil)
              ((eq mode :decrypt)
               (cond
                 ((starts-with "COUNT = " line)
                  (setf (gethash "COUNT" current-case)
                        (parse-integer (subseq line 8))))
                 ((starts-with "KEY = " line)
                  (setf (gethash "KEY" current-case)
                        (hex-string-to-byte-vector (subseq line 6))))
                 ((starts-with "IV = " line)
                  (setf (gethash "IV" current-case)
                        (hex-string-to-byte-vector (subseq line 5))))
                 ((starts-with "CIPHERTEXT = " line)
                  (setf (gethash "CIPHERTEXT" current-case)
                        (hex-string-to-byte-vector (subseq line 12))))
                 ((starts-with "PLAINTEXT = " line)
                  (setf (gethash "PLAINTEXT" current-case)
                        (hex-string-to-byte-vector (subseq line 11)))
		  (when verbose
                    (format t "~%Parsed CFB8 test case ~D" (gethash "COUNT" current-case)))
                  (push current-case cases)
                  (setf current-case (make-hash-table :test 'equal)))))))
      (nreverse cases))))

(defun parse128-cfb1-rsp (filename &optional verbose)
  "Parses a NIST CFB1 .rsp file and returns a list of ENCRYPT test cases."
  (with-open-file (stream filename)
    (let ((cases '())
          (current-case (make-hash-table :test 'equal))
          (mode :skip))
      (loop for line = (read-line stream nil)
            while line do
            (cond
              ((starts-with "[" line)
               (cond
                 ((string= line "[ENCRYPT]") (setf mode :encrypt))
                 ((string= line "[DECRYPT]") (setf mode :skip))))
              ((string= line "") nil)
              ((eq mode :encrypt)
               (cond
                 ((starts-with "COUNT = " line)
                  (setf (gethash "COUNT" current-case)
                        (parse-integer (subseq line 8))))
                 ((starts-with "KEY = " line)
                  (setf (gethash "KEY" current-case)
                        (hex-string-to-byte-vector (subseq line 6))))
                 ((starts-with "IV = " line)
                  (setf (gethash "IV" current-case)
                        (hex-string-to-byte-vector (subseq line 5))))
                 ((starts-with "PLAINTEXT = " line)
                  (setf (gethash "PLAINTEXT" current-case)
                        (bitstring-to-byte-vector (subseq line 11)))
		  (setf (gethash "PLAINTEXT-BITS" current-case)
			(length (string-trim '(#\Space #\Tab #\Return #\Newline) (subseq line 11)))))
                 ((starts-with "CIPHERTEXT = " line)
                  (setf (gethash "CIPHERTEXT" current-case)
                        (bitstring-to-byte-vector (subseq line 12)))
		  (setf (gethash "CIPHERTEXT-BITS" current-case)
			(length (string-trim '(#\Space #\Tab #\Return #\Newline) (subseq line 12))))
		  (when verbose
                    (format t "~%Parsed CFB1 test case ~D" (gethash "COUNT" current-case)))
                  (push current-case cases)
                  (setf current-case (make-hash-table :test 'equal)))))))
      (nreverse cases))))

(defun parse128-cfb1-rsp-decrypt (filename &optional verbose)
  "Parses a NIST CFB1 .rsp file and returns a list of DECRYPT test cases."
  (with-open-file (stream filename)
    (let ((cases '())
          (current-case (make-hash-table :test 'equal))
          (mode :skip))
      (loop for line = (read-line stream nil)
            while line do
            (cond
              ((starts-with "[" line)
               (cond
                 ((string= line "[DECRYPT]") (setf mode :decrypt))
                 ((string= line "[ENCRYPT]") (setf mode :skip))))
              ((string= line "") nil)
              ((eq mode :decrypt)
               (cond
                 ((starts-with "COUNT = " line)
                  (setf (gethash "COUNT" current-case)
                        (parse-integer (subseq line 8))))
                 ((starts-with "KEY = " line)
                  (setf (gethash "KEY" current-case)
                        (hex-string-to-byte-vector (subseq line 6))))
                 ((starts-with "IV = " line)
                  (setf (gethash "IV" current-case)
                        (hex-string-to-byte-vector (subseq line 5))))
                 ((starts-with "CIPHERTEXT = " line)
                  (setf (gethash "CIPHERTEXT" current-case)
                        (bitstring-to-byte-vector (subseq line 12)))
		  (setf (gethash "CIPHERTEXT-BITS" current-case)
			(length (string-trim '(#\Space #\Tab #\Return #\Newline) (subseq line 12)))))
                 ((starts-with "PLAINTEXT = " line)
                  (setf (gethash "PLAINTEXT" current-case)
                        (bitstring-to-byte-vector (subseq line 11)))
		  (setf (gethash "PLAINTEXT-BITS" current-case)
			(length (string-trim '(#\Space #\Tab #\Return #\Newline) (subseq line 11))))
		  (when verbose
                    (format t "~%Parsed CFB1 test case ~D" (gethash "COUNT" current-case)))
                  (push current-case cases)
                  (setf current-case (make-hash-table :test 'equal)))))))
      (nreverse cases))))

(defun parse128-gcm-rsp (filename)
  "Parses NIST AES-GCM encryption RSP file with header support. Returns list of test cases."
  (with-open-file (stream filename)
    (let ((cases '())
          (current (make-hash-table :test 'equal))
          (header  (make-hash-table :test 'equal)))
      (loop for line = (read-line stream nil)
            while line do
            (cond
              ;; Header lines like [Taglen = 128], [AADlen = 160]
	      ((bracketed-line-p line)
	       (handler-case
		   (let* ((eq-pos (position #\= line))
			  ;; Safely slice the key from inside brackets
			  (raw-key (and eq-pos
					(string-trim '(#\[ #\] #\Space #\Tab #\Newline #\Return)
						     (subseq line 0 eq-pos))))
			  ;; Clean and parse the value (after '=' up to ']')
			  (raw-val (and eq-pos
					(string-trim '(#\[ #\] #\Space #\Tab #\Newline #\Return)
						     (subseq line (1+ eq-pos)))))
			  ;; Final key: consistent casing, no trailing space
			  (key (and raw-key raw-key))
			  ;; Attempt to parse value as integer
			  (value (and raw-val
				      (ignore-errors
					(parse-integer raw-val)))))
		     (when (and key value)
		       (setf (gethash key header) value)))
		 (error (e)
		   (format t "~%⚠️ Failed to parse header line: ~A -- ~A" line e))))
              ;; Blank line: reset header for the next block
              ((string= line "") nil)
              ;; Start of a new test case
              ((starts-with "Count = " line)
	       (setf (gethash "Count" current) (parse-integer (subseq line 8))))
              ((starts-with "Key = " line)
               (setf (gethash "Key" current)
                     (hex-string-to-byte-vector (subseq line 6))))
              ((starts-with "IV = " line)
               (setf (gethash "IV" current)
                     (hex-string-to-byte-vector (subseq line 5))))
              ((starts-with "PT = " line)
               (setf (gethash "Plaintext" current)
                     (hex-string-to-byte-vector (subseq line 5))))
              ((starts-with "AAD = " line)
               (setf (gethash "AAD" current)
                     (hex-string-to-byte-vector (subseq line 6))))
              ((starts-with "CT = " line)
               (setf (gethash "Ciphertext" current)
                     (hex-string-to-byte-vector (subseq line 5))))
              ((starts-with "Tag = " line)
               (setf (gethash "Tag" current)
                     (hex-string-to-byte-vector (subseq line 6)))
	       ;; Merge header into current immediately
	       (maphash (lambda (k v)
			  (setf (gethash k current) v))
			header)
               (push current cases)
               (setf current (make-hash-table :test 'equal)))))
      (nreverse cases))))

(defun parse128-gcm-rsp-decrypt (filename)
  "Parses NIST AES-GCM decryption RSP file with header support. Returns list of test cases."
  (with-open-file (stream filename)
    (let ((cases '())
          (current (make-hash-table :test 'equal))
          (header  (make-hash-table :test 'equal)))
      (loop for line = (read-line stream nil)
            while line do
            (cond
              ;; Header lines
	      ((bracketed-line-p line)
	       (handler-case
		   (let* ((eq-pos (position #\= line))
			  ;; Safely slice the key from inside brackets
			  (raw-key (and eq-pos
					(string-trim '(#\[ #\] #\Space #\Tab #\Newline #\Return)
						     (subseq line 0 eq-pos))))
			  ;; Clean and parse the value (after '=' up to ']')
			  (raw-val (and eq-pos
					(string-trim '(#\[ #\] #\Space #\Tab #\Newline #\Return)
						     (subseq line (1+ eq-pos)))))
			  ;; Final key: consistent casing, no trailing space
			  (key (and raw-key raw-key))
			  ;; Attempt to parse value as integer
			  (value (and raw-val
				      (ignore-errors
					(parse-integer raw-val)))))
		     (when (and key value)
		       (setf (gethash key header) value)))
		 (error (e)
		   (format t "~%⚠️ Failed to parse header line: ~A -- ~A" line e))))
	      ;; Blank line: reset header
	      ((string= line "") nil)
	      ;; Start of a test case
	      ((starts-with "Count = " line)
	       (setf (gethash "Count" current) (parse-integer (subseq line 8))))
	      ((starts-with "Key = " line)
	       (setf (gethash "Key" current)
		     (hex-string-to-byte-vector (subseq line 6))))
	      ((starts-with "IV = " line)
	       (setf (gethash "IV" current)
		     (hex-string-to-byte-vector (subseq line 5))))
	      ((starts-with "CT = " line)
	       (setf (gethash "Ciphertext" current)
		     (hex-string-to-byte-vector (subseq line 5))))
	      ((starts-with "AAD = " line)
	       (setf (gethash "AAD" current)
		     (hex-string-to-byte-vector (subseq line 6))))
	      ((starts-with "Tag = " line)
	       (setf (gethash "Tag" current)
		     (hex-string-to-byte-vector (subseq line 6))))
	      ((starts-with "PT = " line)
	       (setf (gethash "Plaintext" current)
		     (hex-string-to-byte-vector (subseq line 5)))
	       ;; Merge header values at beginning of case
	       (maphash (lambda (k v)
			  (setf (gethash k current) v))
                        header)
	       (push current cases)
	       (setf current (make-hash-table :test 'equal)))))
      (nreverse cases))))

(defun parse-aes128-cmac-rsp (filename &optional verbose)
  "Parses a NIST CMAC128 .rsp file and returns a list of test cases."
  (with-open-file (stream filename)
    (let ((cases '())
          (current-case (make-hash-table :test 'equal)))
      (loop for line = (read-line stream nil)
            while line do
            (cond
              ((string= line "") nil) ; skip blank lines
              ((starts-with "Count = " line)
               (setf (gethash "Count" current-case)
                     (parse-integer (subseq line 8))))
              ((starts-with "Klen = " line)
               (setf (gethash "Klen" current-case)
                     (parse-integer (subseq line 7))))
              ((starts-with "Mlen = " line)
	       (setf (gethash "Mlen" current-case)
                     (parse-integer (subseq line 7))))
              ((starts-with "Tlen = " line)
               (setf (gethash "Tlen" current-case)
                     (parse-integer (subseq line 7))))
	      ((starts-with "Key = " line)
               (setf (gethash "Key" current-case)
                     (hex-string-to-byte-vector (subseq line 6))))
              ((starts-with "Msg = " line)
               (setf (gethash "Msg" current-case)
                     (hex-string-to-byte-vector (subseq line 6))))
	      ((starts-with "Mac = " line)
               (setf (gethash "Mac" current-case)
                     (hex-string-to-byte-vector (subseq line 6)))
	       (when verbose
		 (format t "~%Parsed CMAC128 test case ~D" (gethash "Count" current-case)))
               (push current-case cases)
               (setf current-case (make-hash-table :test 'equal)))))
      (nreverse cases))))

(defun parse-aes128-cmac-rsp-verify (filename &optional verbose)
  "Parses a NIST CMAC128 .rsp file and returns a list of test cases."
  (with-open-file (stream filename)
    (let ((cases '())
          (current-case (make-hash-table :test 'equal)))
      (loop for line = (read-line stream nil)
            while line do
            (cond
              ((string= line "") nil) ; skip blank lines
              ((starts-with "Count = " line)
               (setf (gethash "Count" current-case)
                     (parse-integer (subseq line 8))))
              ((starts-with "Klen = " line)
               (setf (gethash "Klen" current-case)
                     (parse-integer (subseq line 7))))
              ((starts-with "Mlen = " line)
	       (setf (gethash "Mlen" current-case)
                     (parse-integer (subseq line 7))))
              ((starts-with "Tlen = " line)
               (setf (gethash "Tlen" current-case)
                     (parse-integer (subseq line 7))))
	      ((starts-with "Key = " line)
               (setf (gethash "Key" current-case)
                     (hex-string-to-byte-vector (subseq line 6))))
              ((starts-with "Msg = " line)
               (setf (gethash "Msg" current-case)
                     (hex-string-to-byte-vector (subseq line 6))))
	      ((starts-with "Mac = " line)
               (setf (gethash "Mac" current-case)
                     (hex-string-to-byte-vector (subseq line 6))))
	      ((starts-with "Result = " line)
               (setf (gethash "Result" current-case)
		     (string-trim " " (subseq line (length "Result = "))))
	       (when verbose
		 (format t "~%Parsed CMAC128 test case ~D" (gethash "Count" current-case)))
               (push current-case cases)
               (setf current-case (make-hash-table :test 'equal)))))
      (nreverse cases))))
