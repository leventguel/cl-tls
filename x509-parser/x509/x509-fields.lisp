(defpackage :x509-fields
  (:use :cl :shared-utils :sha-utils :der-utils :asn1-utils :rsa-utils
	:sha1 :sha224 :sha256 :sha384 :sha512
	:hmac-sha1 :hmac-sha224 :hmac-sha256 :hmac-sha384 :hmac-sha512
	:der-parser
	:rsa-pkcs1 :rsa-core :rsa-key
	:asn1-types :asn1-schema :asn1-parser :asn1-encoders :asn1-extractors)
  (:export :get-tagged :get-sequence-element
	   :parse-version :parse-serial-number :parse-algorithm
	   :parse-bit-string :parse-validity :parse-extension :maybe-parse-extensions))

(in-package :x509-fields)

(defun get-tagged (seq tag)
  (find-if (lambda (el) (and (consp el) (= (car el) tag))) seq))

(defun get-sequence-element (seq index)
  (nth index seq))

;; field parsers
(defun parse-version (tbs-cert)
  (let ((version-tagged (get-tagged tbs-cert 0)))
    (if version-tagged
        (second version-tagged)
        1))) ; default to v1

(defun parse-serial-number (tbs-cert)
  (get-sequence-element tbs-cert 1))

(defun parse-algorithm (algo-seq)
  (let ((oid (get-sequence-element algo-seq 0)))
    (list :oid oid :name (oid->name oid)))) ; map OID to readable name

(defun parse-bit-string (bit-str)
  (second bit-str)) ; skip unused bits byte

(defun parse-validity (validity-seq)
  (let ((not-before (get-sequence-element validity-seq 0))
        (not-after  (get-sequence-element validity-seq 1)))
    (list :not-before (parse-time not-before)
          :not-after  (parse-time not-after))))

(defun parse-extension (ext-seq)
  (let* ((oid (get-sequence-element ext-seq 0))
         (name (oid->name oid))
         (critical (if (and (> (length ext-seq) 2)
                            (eq (type-of (get-sequence-element ext-seq 1)) 'boolean))
                       (get-sequence-element ext-seq 1)
                       nil))
         (value (get-sequence-element ext-seq (if critical 2 1)))
         (decoded (case name
                    ("SubjectKeyIdentifier" (byte-vector-to-hex-string (getf value :raw)))
                    ;; Add more known extensions here
                    (otherwise value))))
    (list :oid oid :name name :critical critical :value decoded)))

(defun maybe-parse-extensions (tbs-cert)
  (let ((ext-tagged (get-tagged tbs-cert 3))) ;; usually tag [3]
    (when ext-tagged
      (let ((ext-seq (second ext-tagged)))
        (mapcar #'parse-extension ext-seq)))))
