(defpackage :rsa-key
  (:use :cl
	:shared-utils :sha-utils :der-utils :asn1-utils :rsa-utils
	:sha1 :sha224 :sha256 :sha384 :sha512
	:hmac-sha1 :hmac-sha224 :hmac-sha256 :hmac-sha384 :hmac-sha512
	:der-parser
	:asn1-types :asn1-schema :asn1-parser :asn1-encoders :asn1-extractors)
  (:export :extract-rsa-public-key :generate-rsa-keypair
	   :serialize-rsa-private-key :serialize-rsa-public-key
	   :test-key-generation :test-private-key-serizalization))

(in-package :rsa-key)

(defun extract-rsa-public-key (spki)
  ;; Parse the BIT STRING inside SPKI
  ;; Decode the SEQUENCE → (modulus, exponent)
  (let* ((bit-string (nth 1 (getf spki :value)))
         (key-seq (extract-bit-string-sequence (getf bit-string :value)))
         (modulus (getf (first (getf key-seq :value)) :value))
         (exponent (getf (second (getf key-seq :value)) :value)))
    (list :modulus (byte-vector-to-integer modulus)
          :exponent (byte-vector-to-integer exponent))))

(defun generate-rsa-keypair (&optional (bits 2048))
  (let* ((half-bits (/ bits 2))
         (p (rsa-utils:generate-prime half-bits))
         (q (rsa-utils:generate-prime half-bits))
         (n (* p q))
         (phi (* (1- p) (1- q)))
         (e 65537)
         (d (rsa-utils:mod-inverse e phi)))
    (unless d
      (error "Failed to compute modular inverse for RSA key"))
    (list :modulus n
          :public-exponent e
          :private-exponent d
          :p p
          :q q
          :phi phi)))

(defun serialize-rsa-private-key (keypair)
  (let* ((n (getf keypair :modulus))
         (e (getf keypair :public-exponent))
         (d (getf keypair :private-exponent))
         (p (getf keypair :p))
         (q (getf keypair :q))
         (exp1 (mod d (1- p)))
         (exp2 (mod d (1- q)))
         (coeff (rsa-utils:mod-inverse q p)))
    (asn1-encoders:encode-sequence
     (asn1-encoders:encode-integer 0)      ;; version
     (asn1-encoders:encode-integer n)
     (asn1-encoders:encode-integer e)
     (asn1-encoders:encode-integer d)
     (asn1-encoders:encode-integer p)
     (asn1-encoders:encode-integer q)
     (asn1-encoders:encode-integer exp1)
     (asn1-encoders:encode-integer exp2)
     (asn1-encoders:encode-integer coeff))))

(defun serialize-rsa-public-key (keypair)
  (asn1-encoders:encode-sequence
   (asn1-encoders:encode-integer (getf keypair :modulus))
   (asn1-encoders:encode-integer (getf keypair :public-exponent))))

(defun test-key-generation ()
  (let ((keypair (generate-rsa-keypair)))
    (format t "~%Modulus (n): ~A" (getf keypair :modulus))
    (format t "~%Public Exponent (e): ~A" (getf keypair :public-exponent))
    (format t "~%Private Exponent (d): ~A" (getf keypair :private-exponent))))

(defun test-private-key-serialization ()
  (let ((keypair (generate-rsa-keypair)))
    (serialize-rsa-private-key keypair)))

(defun test-public-key-serialization ()
  (let ((keypair (generate-rsa-keypair)))
    (serialize-rsa-public-key keypair)))
