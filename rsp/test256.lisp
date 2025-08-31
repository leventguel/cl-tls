(defpackage :aes256rsp-test
  (:use :cl :parse-utils :shared-utils :tls-aes-utils :tls-aes256 :tls-aes-ghash :tls-aes256-gcm :tls-aes256-mac
	:tls-aes-rsp256-parser)
  (:export :test-ecb256-rsp :test-ecb256-rsp-decrypt :test-cbc256-rsp :test-cbc256-rsp-decrypt
	   :test-ctr256-rsp :test-ctr256-rsp-decrypt :test-ofb256-rsp :test-ofb256-rsp-decrypt
	   :test-cfb256-rsp :test-cfb256-rsp-decrypt
	   :test256-cfb8-rsp :test256-cfb8-rsp-decrypt
	   :test256-cfb1-rsp :test256-cfb1-rsp-decrypt
	   :test256-gcm-rsp :test256-gcm-rsp-decrypt
	   :test-aes256-cmac-rsp :test-aes256-cmac-rsp-verify))

(in-package :aes256rsp-test)

(defun test-ecb256-rsp (filename)
  "Runs ECB encryption tests from a NIST .rsp file."
  (let ((cases (parse-ecb256-rsp filename))
        (pass 0)
        (fail 0))
    (dolist (case cases)
      (let* ((key (gethash "KEY" case))
	     (plaintext (gethash "PLAINTEXT" case))
	     (expected-ciphertext (gethash "CIPHERTEXT" case))
	     (expanded-key (expand-key-256 key))
	     (ciphertext (aes256-ecb-encrypt plaintext expanded-key t)))
        (if (equalp ciphertext expected-ciphertext)
	    (incf pass)
	    (progn
	      (incf fail)
	      (format t "~%❌ ECB256 Encrypt Test ~D failed" (gethash "COUNT" case))))))
    (format t "~%✅ ECB256 Encrypt RSP Summary: ~D passed, ~D failed~%" pass fail)))

(defun test-ecb256-rsp-decrypt (filename)
  "Runs ECB decryption tests from a NIST .rsp file."
  (let ((cases (parse-ecb256-rsp-decrypt filename)) ; reuse your existing ECB parser
        (pass 0)
        (fail 0))
    (dolist (case cases)
      (let* ((key (gethash "KEY" case))
	     (expected-plaintext (gethash "PLAINTEXT" case))
	     (ciphertext (gethash "CIPHERTEXT" case))
	     (recovered (aes256-ecb-decrypt ciphertext key t)))
        (if (equalp recovered expected-plaintext)
	    (incf pass)
	    (progn
	      (incf fail)
	      (format t "~%❌ ECB256 Decrypt Test ~D failed" (gethash "COUNT" case))))))
    (format t "~%✅ ECB256 DECRYPT RSP Summary: ~D passed, ~D failed~%" pass fail)))

(defun test-cbc256-rsp (filename)
  (let ((cases (parse-cbc256-rsp filename))
        (pass 0)
        (fail 0))
    (dolist (case cases)
      (let* ((key (gethash "KEY" case))
	     (iv (gethash "IV" case))
	     (plaintext (gethash "PLAINTEXT" case))
	     (expected-ciphertext (gethash "CIPHERTEXT" case))
	     (ciphertext (aes256-cbc-encrypt plaintext key iv t))
	     (recovered (aes256-cbc-decrypt ciphertext key iv t)))
        (if (and (equalp ciphertext expected-ciphertext)
                 (equalp plaintext recovered))
	    (incf pass)
	    (progn
	      (incf fail)
	      (format t "~%❌ CBC256 Encrypt Test ~D failed" (gethash "COUNT" case))))))
    (format t "~%✅ CBC256 Encrypt RSP Summary: ~D passed, ~D failed~%" pass fail)))

(defun test-cbc256-rsp-decrypt (filename)
  "Runs CBC decryption tests from a NIST .rsp file."
  (let ((cases (parse-cbc256-rsp-decrypt filename))
        (pass 0)
        (fail 0))
    (dolist (case cases)
      (let* ((key (gethash "KEY" case))
	     (iv (gethash "IV" case))
	     (ciphertext (gethash "CIPHERTEXT" case))
	     (expected-plaintext (gethash "PLAINTEXT" case))
	     (recovered (aes256-cbc-decrypt ciphertext key iv t)))
        (if (equalp recovered expected-plaintext)
	    (incf pass)
	    (progn
	      (incf fail)
	      (format t "~%❌ CBC256 Decrypt Test ~D failed" (gethash "COUNT" case))))))
    (format t "~%✅ CBC256 DECRYPT RSP Summary: ~D passed, ~D failed~%" pass fail)))

(defun test-ctr256-rsp (filename)
  "Runs CTR encryption tests from a NIST .rsp file."
  (let ((cases (parse-ctr256-rsp filename))
        (pass 0)
        (fail 0))
    (dolist (case cases)
      (let* ((key (gethash "KEY" case))
	     (iv (gethash "IV" case))
	     (plaintext (gethash "PLAINTEXT" case))
	     (expected-ciphertext (gethash "CIPHERTEXT" case))
	     (ciphertext (aes256-ctr-encrypt plaintext key iv)))
        (if (equalp ciphertext expected-ciphertext)
	    (incf pass)
	    (progn
	      (incf fail)
	      (format t "~%❌ CTR256 ENCRYPT Test ~D failed" (gethash "COUNT" case))))))
    (format t "~%✅ CTR256 ENCRYPT Summary: ~D passed, ~D failed~%" pass fail)))

(defun test-ctr256-rsp-decrypt (filename)
  "Runs CTR decryption tests from a NIST .rsp file."
  (let ((cases (parse-ctr256-rsp-decrypt filename))
        (pass 0)
        (fail 0))
    (dolist (case cases)
      (let* ((key (gethash "KEY" case))
	     (iv (gethash "IV" case))
	     (ciphertext (gethash "CIPHERTEXT" case))
	     (expected-plaintext (gethash "PLAINTEXT" case))
	     (recovered (aes256-ctr-decrypt ciphertext key iv)))
        (if (equalp recovered expected-plaintext)
	    (incf pass)
	    (progn
	      (incf fail)
	      (format t "~%❌ CTR256 DECRYPT Test ~D failed" (gethash "COUNT" case))))))
    (format t "~%✅ CTR256 DECRYPT Summary: ~D passed, ~D failed~%" pass fail)))

(defun test-ofb256-rsp (filename)
  "Runs OFB128 encryption tests from a NIST .rsp file."
  (let ((cases (parse-ofb256-rsp filename)) ; use your parser here
        (pass 0)
        (fail 0))
    (dolist (case cases)
      (let* ((key (gethash "KEY" case))
	     (iv (gethash "IV" case))
	     (plaintext (gethash "PLAINTEXT" case))
	     (expected-ciphertext (gethash "CIPHERTEXT" case))
	     (ciphertext (aes256-ofb-encrypt plaintext key iv)))
        (if (equalp ciphertext expected-ciphertext)
	    (incf pass)
	    (progn
	      (incf fail)
	      (format t "~%❌ OFB256 ENCRYPT Test ~D failed" (gethash "COUNT" case))))))
    (format t "~%✅ OFB256 ENCRYPT Summary: ~D passed, ~D failed~%" pass fail)))

(defun test-ofb256-rsp-decrypt (filename)
  "Runs OFB256 decryption tests from a NIST .rsp file."
  (let ((cases (parse-ofb256-rsp-decrypt filename))
        (pass 0)
        (fail 0))
    (dolist (case cases)
      (let* ((key (gethash "KEY" case))
	     (iv (gethash "IV" case))
	     (ciphertext (gethash "CIPHERTEXT" case))
	     (expected-plaintext (gethash "PLAINTEXT" case))
	     (recovered (aes256-ofb-decrypt ciphertext key iv)))
        (if (equalp recovered expected-plaintext)
	    (incf pass)
	    (progn
	      (incf fail)
	      (format t "~%❌ OFB256 DECRYPT Test ~D failed" (gethash "COUNT" case))))))
    (format t "~%✅ OFB256 DECRYPT Summary: ~D passed, ~D failed~%" pass fail)))

(defun test-cfb256-rsp (filename)
  "Runs CFB256 encryption tests from a NIST .rsp file."
  (let ((cases (parse-cfb256-rsp filename))
        (pass 0)
        (fail 0))
    (dolist (case cases)
      (let* ((key (gethash "KEY" case))
	     (iv (gethash "IV" case))
	     (plaintext (gethash "PLAINTEXT" case))
	     (expected-ciphertext (gethash "CIPHERTEXT" case))
	     (ciphertext (aes256-cfb-encrypt plaintext key iv)))
        (if (equalp ciphertext expected-ciphertext)
	    (incf pass)
	    (progn
	      (incf fail)
	      (format t "~%❌ CFB256 ENCRYPT Test ~D failed" (gethash "COUNT" case))))))
    (format t "~%✅ CFB256 ENCRYPT Summary: ~D passed, ~D failed~%" pass fail)))

(defun test-cfb256-rsp-decrypt (filename)
  "Runs CFB128 decryption tests from a NIST .rsp file."
  (let ((cases (parse-cfb256-rsp-decrypt filename))
        (pass 0)
        (fail 0))
    (dolist (case cases)
      (let* ((key (gethash "KEY" case))
	     (iv (gethash "IV" case))
	     (ciphertext (gethash "CIPHERTEXT" case))
	     (expected-plaintext (gethash "PLAINTEXT" case))
	     (recovered (aes256-cfb-decrypt ciphertext key iv)))
        (if (equalp recovered expected-plaintext)
	    (incf pass)
	    (progn
	      (incf fail)
	      (format t "~%❌ CFB256 DECRYPT Test ~D failed" (gethash "COUNT" case))))))
    (format t "~%✅ CFB256 DECRYPT Summary: ~D passed, ~D failed~%" pass fail)))

(defun test256-cfb8-rsp (filename)
  (let ((cases (parse256-cfb8-rsp filename))
        (pass 0)
        (fail 0))
    (dolist (case cases)
      (let ((ciphertext (aes256-cfb8-xcrypt
                         (gethash "PLAINTEXT" case)
                         (gethash "KEY" case)
                         (gethash "IV" case))))
        (if (equalp ciphertext (gethash "CIPHERTEXT" case))
	    (incf pass)
	    (progn (incf fail)
		   (format t "~%❌ CFB8 ENCRYPT Test ~D failed" (gethash "COUNT" case))))))
    (format t "~%✅ CFB8 ENCRYPT Summary: ~D passed, ~D failed~%" pass fail)))

(defun test256-cfb8-rsp-decrypt (filename)
  (let ((cases (parse256-cfb8-rsp-decrypt filename))
        (pass 0)
        (fail 0))
    (dolist (case cases)
      (let ((recovered (aes256-cfb8-xcrypt
                        (gethash "CIPHERTEXT" case)
                        (gethash "KEY" case)
                        (gethash "IV" case)
                        :decrypt t)))
        (if (equalp recovered (gethash "PLAINTEXT" case))
	    (incf pass)
	    (progn (incf fail)
		   (format t "~%❌ CFB8 DECRYPT Test ~D failed" (gethash "COUNT" case))))))
    (format t "~%✅ CFB8 DECRYPT Summary: ~D passed, ~D failed~%" pass fail)))

(defun test256-cfb1-rsp (filename)
  (let ((cases (parse256-cfb1-rsp filename))
        (pass 0)
        (fail 0))
    (dolist (case cases)
      (let ((ciphertext (aes256-cfb1-xcrypt
                         (gethash "PLAINTEXT" case)
                         (gethash "KEY" case)
                         (gethash "IV" case)))
	    (bit-count (gethash "CIPHERTEXT-BITS" case)))
        (if (bits-equal-p ciphertext (gethash "CIPHERTEXT" case) bit-count)
	    (incf pass)
	    (progn (incf fail)
		   (format t "~%❌ CFB1 ENCRYPT Test ~D failed" (gethash "COUNT" case))))))
    (format t "~%✅ CFB1 ENCRYPT Summary: ~D passed, ~D failed~%" pass fail)))

(defun test256-cfb1-rsp-decrypt (filename)
  (let ((cases (parse256-cfb1-rsp-decrypt filename))
        (pass 0)
        (fail 0))
    (dolist (case cases)
      (let ((recovered (aes256-cfb1-xcrypt
                        (gethash "CIPHERTEXT" case)
                        (gethash "KEY" case)
                        (gethash "IV" case)
                        :decrypt t))
	    (bit-count (gethash "PLAINTEXT-BITS" case)))
        (if (bits-equal-p recovered (gethash "PLAINTEXT" case) bit-count)
	    (incf pass)
	    (progn (incf fail)
		   (format t "~%❌ CFB1 DECRYPT Test ~D failed" (gethash "COUNT" case))))))
    (format t "~%✅ CFB1 DECRYPT Summary: ~D passed, ~D failed~%" pass fail)))

(defun test256-gcm-rsp (filename &optional verbose-p)
  "Runs AES-GCM encryption tests from NIST RSP file."
  (let ((cases (parse256-gcm-rsp filename))
        (pass 0)
        (fail 0))
    (dolist (case cases)
      (let* ((taglen   (or (gethash "Taglen" case) 128))
	     (aad      (gethash "AAD" case))
	     (aad-len  (or (gethash "AADlen" case) (length aad)))
	     (pt       (gethash "Plaintext" case))
	     (ctlen    (length pt)))
	(handler-case
            (multiple-value-bind (ct tag)
		(aes256-gcm-encrypt pt
				    (gethash "Key" case)
				    (gethash "IV" case)
				    aad
				    taglen
				    aad-len
				    ctlen
				    verbose-p)
	      
	      ;; 🔍 Add this comparison logging here:
	      (when verbose-p
		(progn
		  (format t "~%Test ~D uses     : taglen = ~D, aad-len = ~D and ⏎~%AAD              : ~A"
			  (gethash "Count" case)
			  (gethash "Taglen" case)
			  (gethash "AADlen" case)
			  (byte-vector-to-hex-string (gethash "AAD" case)))
		  (format t "~&~%Expected tag     : ~A" (byte-vector-to-hex-string (gethash "Tag" case)))
		  (format t "~%Computed tag     : ~A" (byte-vector-to-hex-string tag))))
	      
	      (if (and (equalp ct (gethash "Ciphertext" case))
		       (equalp tag (gethash "Tag" case)))
		  (progn
                    (incf pass)
		    (when verbose-p
                      (format t "~%✅ Encrypt Test ~D passed!" (gethash "Count" case))))
		  (progn
                    (incf fail)
		    (when verbose-p
                      (format t "~%❌ Encrypt Test ~D failed!!!!!!!!!" (gethash "Count" case))))))
	  (error ()
	    (progn
	      (incf fail)
	      (format t "~%❌ Encrypt Test ~D failed!!!!!!!!" (gethash "Count" case)))))))
    (format t "~&~%🧾 AES256 GCM Encrypt -~&Summary: ~D passed, ~D failed~%" pass fail)))

(defun test256-gcm-rsp-decrypt (filename &optional verbose-p)
  "Runs AES-GCM decryption tests from NIST RSP file."
  (let ((cases (parse256-gcm-rsp-decrypt filename))
        (pass 0)
        (fail 0))
    (dolist (case cases)
      (let* ((taglen   (or (gethash "Taglen" case) 128))
	     (aad      (gethash "AAD" case))
	     (aad-len  (or (gethash "AADlen" case) (length aad)))
	     (ct       (gethash "Ciphertext" case))
	     (ctlen    (length ct)))
        (handler-case
	    (multiple-value-bind (pt tag)
		(aes256-gcm-decrypt ct
				    (gethash "Key" case)
				    (gethash "IV" case)
				    (gethash "Tag" case)
				    aad
				    taglen
				    aad-len
				    ctlen
				    verbose-p)

	      ;; 🔍 Add this comparison logging here:
	      (when verbose-p
		(progn
		  (format t "~%Test ~D uses     : taglen = ~D, aad-len = ~D and ⏎~%AAD              : ~A"
			  (gethash "Count" case)
			  (gethash "Taglen" case)
			  (gethash "AADlen" case)
			  (byte-vector-to-hex-string (gethash "AAD" case)))
		  (format t "~&~%Expected tag     : ~A" (byte-vector-to-hex-string (gethash "Tag" case)))
		  (format t "~%Computed tag     : ~A" (byte-vector-to-hex-string tag))))

	      (if (equalp pt (gethash "Plaintext" case))
		  (progn
		    (incf pass)
		    (when verbose-p
		      (format t "~%✅ Decrypt Test ~D passed" (gethash "Count" case))))
		  (progn
		    (incf fail)
		    (when verbose-p
		      (format t "~%❌ Decrypt Test ~D failed (mismatched plaintext)" (gethash "Count" case))))))
	  (error ()
	    (progn
	      (incf fail)
	      (format t "~%❌ Decrypt Test ~D failed (tag verification error)" (gethash "Count" case)))))))
    (format t "~%🧾 AES256 GCM Decrypt Summary: ~D passed, ~D failed~%" pass fail)))

(defun test-aes256-cmac-rsp (filename)
  (let ((cases (parse-aes256-cmac-rsp filename))
        (pass 0)
        (fail 0))
    (dolist (case cases)
      (let* ((key (gethash "Key" case))
             (msg (if (= 0 (gethash "Mlen" case)) #() (gethash "Msg" case)))
             (expected-mac (gethash "Mac" case))
             (tlen (gethash "Tlen" case))
	     (computed-mac (cmac-aes256 msg key tlen)))  ; Your CMAC function
        (if (equalp computed-mac expected-mac)
	    (incf pass)
	    (progn
	      (incf fail)
	      (format t "~%❌ CMAC256 Test ~D failed" (gethash "Count" case))))))
    (format t "~%✅ CMAC256 RSP Summary: ~D passed, ~D failed~%" pass fail)))

(defun test-aes256-cmac-rsp-verify (filename)
  (let ((cases (parse-aes256-cmac-rsp-verify filename))
        (pass 0)
        (fail 0))
    (dolist (case cases)
      (let* ((key (gethash "Key" case))
             (msg (if (= 0 (gethash "Mlen" case)) #() (gethash "Msg" case)))
             (expected-mac (gethash "Mac" case))
             (tlen (gethash "Tlen" case))
             (expected-result (gethash "Result" case))
             (computed-mac (cmac-aes256 msg key tlen))
             (match (equalp computed-mac expected-mac))
             (should-pass (string= expected-result "P")))
        (if (eq match should-pass)
            (incf pass)
            (progn
              (incf fail)
              (format t "~%❌ CMAC Verify Test ~D failed (expected ~A, got ~A)"
                      (gethash "Count" case)
                      expected-result
                      (if match "P" "F"))))))
    (format t "~%✅ CMAC256 Verify Summary: ~D passed, ~D failed~%" pass fail)))
