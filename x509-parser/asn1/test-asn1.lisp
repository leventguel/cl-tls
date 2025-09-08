(defpackage :test-asn1
  (:use :cl
	:shared-utils
	:sha1 :sha224 :sha256 :sha384 :sha512
	:hmac-sha1 :hmac-sha224 :hmac-sha256 :hmac-sha384 :hmac-sha512
	:rsa-pkcs1
	:asn1-types :asn1-schema :asn1-utils :asn1-parser :asn1-extractors :asn1-encoders)
  (:export :run-asn1-tests))

(in-package :test-asn1)

(defun run-asn1-tests (&optional (path "x509-parser/asn1/test-cert.der"))
  (let* ((stream (read-file-as-byte-stream path))
         (parsed (parse-asn1-element stream)))
    (format t "~%Parsed ASN.1 Tree:")
    (print-asn1-tree parsed)
    (format t "~%Extracted Printable Values: ~A~%" (extract-printable-values parsed))))

(defun test-tbs-schema ()
  (let ((stream (read-file-as-byte-stream "x509-parser/asn1/test-cert.der"))
	(schema *certificate-schema*))
    (declare (ignore schema))
    (let ((parsed (parse-asn1-element stream)))
      ;;(print-asn1-tree parsed)
      (let ((tbs (first (getf parsed :value)))) ; ← this is the TBSCertificate
	(if (match-schema tbs schema)
            (format t "~%✅ TBSCertificate matches schema.")
            (format t "~%❌ TBSCertificate does NOT match schema.")))
      (if (match-schema parsed *full-certificate-schema*)
	  (format t "~%✅ Full certificate matches schema.")
	  (format t "~%❌ Full certificate does NOT match schema.")))))

(defun format-extension (ext)
  (let ((decoded (decode-extension-value (getf ext :raw-value))))
    (cond
      ((string= (string (getf ext :oid)) "subjectKeyIdentifier")
       (format t "~% subjectKeyIdentifier:")
       (format t "~%  Decoded payload:")
      (dolist (entry (decode-subject-key-identifier decoded))
	(format t "~%   ~28A: ~A~%" (getf entry :type) (getf entry :value))))
      
      ((string= (string (getf ext :oid)) "authorityKeyIdentifier")
       (format t "~% authorityKeyIdentifier:")
       (format t "~%  Decoded payload:")
       (dolist (entry (decode-authority-key-identifier decoded))
         (format t "~%   ~28A: ~A~%" (getf entry :type) (getf entry :value))))
      
      ((string= (string (getf ext :oid)) "basicConstraints")
       (format t "~% basicConstraints:")
       (format t "~%  Decoded payload:")
       (dolist (entry (decode-basic-constraints decoded))
         (format t "~%   ~28A: ~A~%" (getf entry :type) (getf entry :value))))
      
      ((string= (string (getf ext :oid)) "subjectAltName")
       (format t "~% subjectAltName:")
       (format t "~%  Decoded payload:")
       (dolist (entry (decode-general-names decoded))
         (format t "~%   ~28A: ~A" (getf entry :type) (getf entry :value))))
      (t
       (format t "~% ~A: (unhandled extension)" (getf ext :oid))))))

(defun test-cert-1 ()
  (let ((stream (read-file-as-byte-stream "x509-parser/asn1/test-cert.der"))
	(schema *certificate-schema*))
    (declare (ignore schema))
    ;;(print-asn1-tree parsed)
    (let* ((parsed (parse-asn1-element stream))
	   (tbs (first (getf parsed :value))) ;; ← this is the TBSCertificate
	   (tbs-start (+ (getf tbs :start-pos) 4))
	   (tbs-length (getf tbs :length))
	   (tbs-total-length (getf tbs :total-length))
	   (subject (nth 5 (getf tbs :value))) ;; subject is the 6th element in TBSCertificate
	   (issuer (nth 3 (getf tbs :value)))
	   (spki (nth 6 (getf tbs :value)))
	   (ext-block (extract-extensions-block tbs))
	   (tbs-raw (extract-raw-tbs (byte-stream-data stream) parsed)))
      (let* ((extracted-subject (extract-subject-fields subject))
	     (extracted-issuer (extract-subject-fields issuer))
	     (info (extract-public-key-info spki))
	     (max-key-width
	      (reduce #'max (mapcar (lambda (pair)
				      (length (princ-to-string (car pair))))
				    extracted-subject)))
	     (validity (nth 4 (getf tbs :value)))
	     (dates (extract-validity validity))
	     (dates-raw (extract-validity-raw validity))) ; validity is 5th in TBSCertificate

	;;(format t "~%RAW TBS: ~a~%" tbs-raw)
	(terpri)
	(format t "~%Subject fields:")
	(dolist (pair extracted-subject)
	  (format t "~%  ~vA = ~A"
		  max-key-width
		  (princ-to-string (car pair))
		  (cdr pair)))
	
	(terpri)
	(format t "~%Validity:")
	(format t "~% Not Before                    : ~A" (getf dates :not-before))
	(format t "~% Not After                     : ~A" (getf dates :not-after))
	(format t "~% Not Before (raw)              : ~A" (getf dates-raw :not-before))
	(format t "~% Not After  (raw)              : ~A" (getf dates-raw :not-after))
	
	(terpri)
	(format t "~%Issuer fields:")
	(dolist (pair extracted-issuer)
	  (format t "~%  ~vA = ~A"
		  max-key-width
		  (princ-to-string (car pair))
		  (cdr pair)))
	
	(terpri)
	(format t "~%Public Key Info:")
	(format t "~% Algorithm                     : ~24A" (getf info :algorithm))
	(format t "~% Key Bytes                     : ~24A" (subseq (getf info :key-bytes) 0 16)) ; preview
	(format t "  ... (~D bytes total)" (length (getf info :key-bytes)))
	
	(when ext-block
	  (terpri)
	  (format t "~%Extensions:")
	  (dolist (ext (extract-extensions ext-block))
	    (format-extension ext)))))))

(defun test-cert-2 ()
  (let ((stream (read-file-as-byte-stream "x509-parser/asn1/test-cert.der"))
	(schema *certificate-schema*))
    (declare (ignore schema))
    ;;(print-asn1-tree parsed)
    (let* ((parsed (parse-asn1-element stream))
	   (tbs (first (getf parsed :value))) ;; ← this is the TBSCertificate
	   (tbs-start (+ (getf tbs :start-pos) 4))
	   (tbs-length (getf tbs :length))
	   (tbs-total-length (getf tbs :total-length))
	   (subject (nth 5 (getf tbs :value)))
	   (issuer (nth 3 (getf tbs :value)))
	   (spki (nth 6 (getf tbs :value)))
	   (signature-bitstring (nth 2 (getf parsed :value)))
           (signature-bytes (subseq (getf signature-bitstring :value) 1))
           (rsa-key (rsa-key:extract-rsa-public-key spki))
           (modulus (getf rsa-key :modulus))
           (modulus-size (/ (integer-length modulus) 8))
           (exponent (getf rsa-key :exponent))
           ;;(tbs-bytes (encode-asn1-element tbs))
	   ;;(tbs-bytes (subseq (byte-stream-data stream) tbs-start
	   ;;	    (+ tbs-start tbs-total-length)))
	   (tbs-bytes (extract-element-bytes stream tbs))
           (expected-hash (sha256 tbs-bytes))
           ;;(expected-hash (sha256 (extract-tbs-raw der-bytes)))
           (decrypted-int (rsa-core:rsa-verify (byte-vector-to-integer signature-bytes)
                                               exponent modulus))
           (decrypted-bytes (integer-to-byte-vector decrypted-int modulus-size))
           (digest-info-bytes (strip-pkcs1-padding decrypted-bytes))
           (digest-info (parse-digest-info digest-info-bytes))
	   (ext-block (extract-extensions-block tbs))) ;; subject is the 6th element in TBSCertificate
      (let* ((extracted-subject (extract-subject-fields subject))
	     (extracted-issuer (extract-subject-fields issuer))
	     (info (extract-public-key-info spki))
	     (max-key-width
	      (reduce #'max (mapcar (lambda (pair)
				      (length (princ-to-string (car pair))))
				    extracted-subject)))
	     (validity (nth 4 (getf tbs :value)))
	     (dates (extract-validity validity))
	     (dates-raw (extract-validity-raw validity))) ; validity is 5th in TBSCertificate
	
	(terpri)
	(format t "~%Subject fields:")
	(dolist (pair extracted-subject)
	  (format t "~%  ~vA = ~A"
		  max-key-width
		  (princ-to-string (car pair))
		  (cdr pair)))
	
	(terpri)
	(format t "~%Validity:")
	(format t "~%  Not Before                   : ~A" (getf dates :not-before))
	(format t "~%  Not After                    : ~A" (getf dates :not-after))
	(format t "~%  Not Before (raw)             : ~A" (getf dates-raw :not-before))
	(format t "~%  Not After  (raw)             : ~A" (getf dates-raw :not-after))
	
	(terpri)
	(format t "~%Issuer fields:")
	(dolist (pair extracted-issuer)
	  (format t "~%  ~vA = ~A"
		  max-key-width
		  (princ-to-string (car pair))
		  (cdr pair)))
	
	(terpri)
	(format t "~%Public Key Info:")
	(format t "~% Algorithm                     : ~24A" (getf info :algorithm))
	(format t "~% Key Bytes                     : ~24A" (subseq (getf info :key-bytes) 0 10)) ; preview
	(format t "  ... (~D bytes total)" (length (getf info :key-bytes)))
	
	(when ext-block
	  (terpri)
	  (format t "~%Extensions:")
	  (dolist (ext (extract-extensions ext-block))
	    (format-extension ext))))
      (let ((serial (extract-serial-number tbs))
	    (sig-algo (extract-signature-algorithm tbs)))
	(terpri)
	(format t "~%Serial Number                  : ~A" (byte-vector-to-hex-string serial))
	(format t "~%Signature Algorithm            : ~A" (getf sig-algo :oid))
	(when (getf sig-algo :params)
	  (format t "~%Algorithm Params               : ~A" (getf sig-algo :params))))
      
      (let ((hash (sha256 tbs-bytes)))
	(let ((constructed-digest-info (build-digest-info (getf digest-info :hash))))
	  ;; Compare this to the decrypted signature bytes
	  (format t "~%DigestInfo OID                 : ~A"
		  (getf digest-info :algorithm-oid))
	  (format t "~%DigestInfo Hash                : ~A"
		  (byte-vector-to-hex-string (getf digest-info :hash)))
		(format t "~%TBS full                       : ~A"
			(byte-vector-to-hex-string
			 (sha256 (extract-element-bytes stream tbs))))
		(format t "~%TBS value                      : ~A"
			(byte-vector-to-hex-string
			 (sha256 (subseq (byte-stream-data stream) 4 (+ 4 539)))))
		(format t "~%Lenght TBS value:              : ~A" tbs-length)
		(format t "~%Lenght total TBS               : ~A" (length tbs-bytes))
		(format t "~%constructed/digest-info match? : ~A"
			(equalp constructed-digest-info digest-info-bytes)))))))

(defun test-cert-3 ()
  (let ((stream (read-file-as-byte-stream "x509-parser/asn1/test-cert.der"))
	(schema *certificate-schema*))
    (declare (ignore schema))
    ;;(print-asn1-tree parsed)
    (let* ((parsed (parse-asn1-element stream))
	   (tbs (first (getf parsed :value))) ;; ← this is the TBSCertificate
	   (tbs-start (+ (getf tbs :start-pos) 4))
	   (tbs-length (getf tbs :length))
	   (tbs-total-length (getf tbs :total-length))
	   (subject (nth 5 (getf tbs :value)))
	   (issuer (nth 3 (getf tbs :value)))
	   (spki (nth 6 (getf tbs :value)))
	   (signature-bitstring (nth 2 (getf parsed :value)))
           (signature-bytes (subseq (getf signature-bitstring :value) 1))
           (rsa-key (rsa-key:extract-rsa-public-key spki))
           (modulus (getf rsa-key :modulus))
           (modulus-size (/ (integer-length modulus) 8))
           (exponent (getf rsa-key :exponent))
           ;;(tbs-bytes (encode-asn1-element tbs))
	   (tbs-bytes (subseq (byte-stream-data stream) tbs-start
	 		      (+ tbs-start tbs-total-length)))
	   ;;(tbs-bytes (extract-element-bytes stream tbs))
           (expected-hash (sha256 tbs-bytes))
           ;;(expected-hash (sha256 (extract-tbs-raw der-bytes)))
           (decrypted-int (rsa-core:rsa-verify (byte-vector-to-integer signature-bytes)
                                               exponent modulus))
           (decrypted-bytes (integer-to-byte-vector decrypted-int modulus-size))
           (digest-info-bytes (strip-pkcs1-padding decrypted-bytes))
           (digest-info (parse-digest-info digest-info-bytes)))
      (format t "~%DigestInfo OID                 : ~A" (getf digest-info :algorithm-oid))
      (format t "~%DigestInfo Hash                : ~A" (byte-vector-to-hex-string (getf digest-info :hash)))
      (format t "~%TBS full                       : ~A"
	      (bytes->hex
	       (sha256 (extract-element-bytes stream tbs))))
      (format t "~%TBS value                      : ~A"
	      (byte-vector-to-hex-string
	       (sha256 (subseq (byte-stream-data stream) 4 (+ 4 539)))))
      (format t "~%Match extraced manual          : ~A" (equalp tbs-bytes (extract-element-bytes stream tbs)))
      )))
