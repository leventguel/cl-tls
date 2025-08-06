;; assumes basic DER decoding utilities (no full ASN.1 support)
(defpackage :x509-parser
  (:use :cl :der-parser :x509-fields)
  (:export :get-tagged :get-sequence-element
	   :parse-x509-certificate :parse-name :parse-rdn :parse-subject-public-key-info))

(in-package :x509-parser)

(defun get-tagged (seq tag)
  (find-if (lambda (el) (and (consp el) (= (car el) tag))) seq))

(defun get-sequence-element (seq index)
  (nth index seq))

(defun parse-x509-certificate (der-bytes)
  (let ((seq (parse-der-sequence der-bytes)))
    (let* ((tbs-cert (get-sequence-element seq 0))
           (sig-algo (get-sequence-element seq 1))
           (sig-value (get-sequence-element seq 2))
           (version (parse-version tbs-cert))
           (serial (parse-serial-number tbs-cert))
           (issuer (parse-name (get-sequence-element tbs-cert 3)))
           (validity (parse-validity (get-sequence-element tbs-cert 4)))
           (subject (parse-name (get-sequence-element tbs-cert 5)))
           (spki (parse-subject-public-key-info (get-sequence-element tbs-cert 6)))
           (extensions (maybe-parse-extensions tbs-cert)))
      (list :version version
            :serial-number serial
            :issuer issuer
            :validity validity
            :subject subject
            :subject-public-key-info spki
            :signature-algorithm sig-algo
            :signature-value sig-value
            :extensions extensions))))

;; name and validity

(defun parse-name (name-seq)
  (mapcar #'parse-rdn name-seq))

(defun parse-rdn (rdn-set)
  (mapcar (lambda (attr)
            (let ((oid (get-sequence-element attr 0))
                  (val (get-sequence-element attr 1)))
              (cons (oid->name oid) val)))
          rdn-set))

;; pubkey info
(defun parse-subject-public-key-info (spki-seq)
  (let ((algo (get-sequence-element spki-seq 0))
        (bit-str (get-sequence-element spki-seq 1)))
    (let ((key-seq (parse-der-sequence (parse-bit-string bit-str))))
      (list :modulus (get-sequence-element key-seq 0)
            :exponent (get-sequence-element key-seq 1)))))
