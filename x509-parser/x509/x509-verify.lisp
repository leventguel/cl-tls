(defpackage :x509-verify
  (:use :cl
	:shared-utils :sha-utils :der-utils :asn1-utils :rsa-utils
	:sha1 :sha224 :sha256 :sha384 :sha512
	:hmac-sha1 :hmac-sha224 :hmac-sha256 :hmac-sha384 :hmac-sha512
	:der-parser
	:rsa-pkcs1 :rsa-core :rsa-key
	:asn1-types :asn1-schema :asn1-parser :asn1-encoders :asn1-extractors)
  (:export :*digest-algorithms* :compute-digest
	   :verify-certificate-signature :verify-self-signed-certificate))

(in-package :x509-verify)

(defparameter *digest-algorithms*
  '(("SHA-1"     . (sha1     . sha1->bytes))
    ("SHA-224"   . (sha224   . sha224->bytes))
    ("SHA-256"   . (sha256   . sha256->bytes))
    ("SHA-384"   . (sha384   . sha384->bytes))
    ("SHA-512"   . (sha512   . sha512->bytes))))

(defun compute-digest (algorithm-name data)
  (let ((entry (assoc algorithm-name *digest-algorithms* :test #'string=)))
    (if entry
        (funcall (cdr (cdr entry)) (funcall (car (cdr entry)) data))
        (error "Unsupported digest algorithm: ~A" algorithm-name))))

(defun verify-signature (tbs-bytes signature-bytes rsa-key)
  (let* ((modulus (getf rsa-key :modulus))
         (modulus-size (/ (integer-length modulus) 8))
         (exponent (getf rsa-key :exponent))
         (decrypted (rsa-core:rsa-verify (byte-vector-to-integer signature-bytes)
                                         exponent modulus))
         (digest-info (parse-digest-info
                       (strip-pkcs1-padding
                        (integer-to-byte-vector decrypted modulus-size))))
	 (algo-name (getf digest-info :algorithm-oid)))
    (equalp (getf digest-info :hash) (compute-digest algo-name tbs-bytes))))

(defun verify-certificate-signature (parsed-cert &optional cert-bytes)
  (let* ((tbs (first (getf parsed-cert :value)))
	 (tbs-start (+ (getf tbs :start-pos) 4))
	 (tbs-length (getf tbs :length))
	 (tbs-total-length (getf tbs :total-length))
         (spki (nth 6 (getf tbs :value)))
         (signature-bitstring (nth 2 (getf parsed-cert :value)))
         (signature-bytes (subseq (getf signature-bitstring :value) 1))
         (rsa-key (rsa-key:extract-rsa-public-key spki))
         (tbs-bytes (subseq cert-bytes
			    tbs-start
			    (+ tbs-start tbs-total-length))))
    (verify-signature tbs-bytes signature-bytes rsa-key)))

(defun verify-self-signed-certificate (cert-bytes)
  (let* ((parsed-cert (parse-asn1-element (make-byte-stream :data cert-bytes)))
         (tbs (first (getf parsed-cert :value)))
	 (tbs-start (+ (getf tbs :start-pos) 4))
	 (tbs-length (getf tbs :length))
	 (tbs-total-length (getf tbs :total-length)))
    (if (equalp (getf tbs :issuer) (getf tbs :subject))
        (progn
          (format t "~%✅ Self-signed certificate detected")
          (verify-certificate-signature parsed-cert cert-bytes))
        (format t "~%⚠️ Not self-signed — cannot verify with embedded key"))))
