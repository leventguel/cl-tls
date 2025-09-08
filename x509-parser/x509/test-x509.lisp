(defpackage :test-x509
  (:use :cl
	:shared-utils :sha-utils :der-utils :asn1-utils :rsa-utils
	:sha1 :sha224 :sha256 :sha384 :sha512
	:hmac-sha1 :hmac-sha224 :hmac-sha256 :hmac-sha384 :hmac-sha512
	:der-parser
	:rsa-pkcs1 :rsa-core :rsa-key
	:asn1-types :asn1-schema :asn1-parser :asn1-encoders :asn1-extractors
	:x509-fields :x509-parser :x509-verify)
  (:export :test-certificate-verification :run-certificate-verification-test))

(in-package :test-x509)

(defun test-certificate-verification (cert-bytes)
  (let* ((parsed-cert (parse-asn1-element (make-byte-stream :data cert-bytes)))
         (tbs (first (getf parsed-cert :value)))
	 (tbs-start (+ (getf tbs :start-pos) 4))
	 (tbs-length (getf tbs :length))
	 (tbs-total-length (getf tbs :total-length))
         (spki (nth 6 (getf tbs :value)))
         (signature-bitstring (nth 2 (getf parsed-cert :value)))
         (signature-bytes (subseq (getf signature-bitstring :value) 1))
         (rsa-key (rsa-key:extract-rsa-public-key spki))
         (modulus (getf rsa-key :modulus))
	 (modulus-size (/ (integer-length modulus) 8))
         (exponent (getf rsa-key :exponent))
         (tbs-bytes (subseq cert-bytes
			    tbs-start
			    (+ tbs-start tbs-total-length)))
         (decrypted-int (rsa-core:rsa-verify
			 (byte-vector-to-integer signature-bytes)
                         exponent modulus))
	 (decrypted-bytes (integer-to-byte-vector decrypted-int modulus-size))
	 (digest-info-bytes (strip-pkcs1-padding decrypted-bytes))
         (digest-info (parse-digest-info digest-info-bytes))
	 (algo-name (getf digest-info :algorithm-oid))
	 (expected-hash (compute-digest algo-name tbs-bytes)))
    (if (equalp (getf digest-info :hash) expected-hash)
        (format t "~%✅ Signature Verified")
        (format t "~%❌ Signature Verification Failed"))))

(with-open-file (in "x509-parser/asn1/test-cert.der" :element-type '(unsigned-byte 8))
  (let ((bytes (make-array (file-length in) :element-type '(unsigned-byte 8))))
    (read-sequence bytes in)
    (test-certificate-verification bytes)))

(defun run-certificate-verification-test (path)
  (with-open-file (in path :element-type '(unsigned-byte 8))
    (let ((bytes (make-array (file-length in) :element-type '(unsigned-byte 8))))
      (read-sequence bytes in)
      (if (verify-self-signed-certificate bytes)
          (format t "~%✅ Signature Verified")
          (format t "~%❌ Signature Verification Failed")))))

(run-certificate-verification-test "x509-parser/asn1/test-cert.der")
