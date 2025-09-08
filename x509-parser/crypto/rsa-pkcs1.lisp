(defpackage :rsa-pkcs1
  (:use :cl
	:shared-utils :sha-utils :der-utils :asn1-utils :rsa-utils
	:sha1 :sha224 :sha256 :sha384 :sha512
	:hmac-sha1 :hmac-sha224 :hmac-sha256 :hmac-sha384 :hmac-sha512
	:der-parser
	:asn1-types :asn1-schema :asn1-parser :asn1-encoders :asn1-extractors)
  (:export :strip-pkcs1-padding :parse-digest-info))

(in-package :rsa-pkcs1)

(defun strip-pkcs1-padding (bytes)
  (if (and (= (aref bytes 0) 0)
           (= (aref bytes 1) 1))
      (let ((index (position 0 bytes :start 2)))
        (if index
            (subseq bytes (1+ index)) ; skip the 0x00 separator
            (error "Invalid PKCS#1 padding: no #x00 found")))
      (error "Invalid PKCS#1 padding: missing #x00 #x01 prefix")))

(defun parse-digest-info (bytes)
  (let* ((stream (make-byte-stream :data bytes))
         (parsed (parse-asn1-element stream)))
    (unless (and (eq (getf parsed :type) :sequence)
                 (getf parsed :constructed))
      (error "Expected DigestInfo to be a SEQUENCE"))
    (let* ((fields (getf parsed :value))
           (algo-id (first fields))
           (digest-field (second fields)))
      (unless (eq (getf digest-field :type) :octet-string)
        (error "Expected second field to be OCTET STRING"))
      (let* ((algo-seq (getf algo-id :value))
             (oid-bytes (getf (first algo-seq) :value))
             (hash-bytes (getf digest-field :value)))
        (list :algorithm (asn1-extractors:oid->name oid-bytes)
              :algorithm-oid (asn1-extractors:oid->name oid-bytes)
              :hash hash-bytes)))))
