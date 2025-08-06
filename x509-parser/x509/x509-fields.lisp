(defpackage :x509-fields
  (:use :cl :der-utils)
  (:export :parse-version :parse-serial-number :parse-algorithm
	   :parse-bit-string :parse-validity :maybe-parse-extensions :parse-extension))

;; field parsers
(defun parse-version (tbs-cert)
  (let ((version-tagged (get-tagged tbs-cert 0)))
    (if version-tagged
        (second version-tagged)
        1))) ; default to v1

(defun parse-serial-number (tbs-cert)
  (get-seqence-element tbs-cert 1))

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

(defun maybe-parse-extensions (tbs-cert)
  (let ((ext-tagged (get-tagged tbs-cert 3))) ;; usually tag [3]
    (when ext-tagged
      (let ((ext-seq (second ext-tagged)))
        (mapcar #'parse-extension ext-seq)))))

(defun parse-extension (ext-seq)
  (let* ((oid (get-seq-element ext-seq 0))
         (name (oid->name oid))
         (critical (if (and (> (length ext-seq) 2)
                            (eq (type-of (get-seq-element ext-seq 1)) 'boolean))
                       (get-seq-element ext-seq 1)
                       nil))
         (value (get-seq-element ext-seq (if critical 2 1)))
         (decoded (case name
                    ("SubjectKeyIdentifier" (bytes-to-hex (getf value :raw)))
                    ;; Add more known extensions here
                    (otherwise value))))
    (list :oid oid :name name :critical critical :value decoded)))
