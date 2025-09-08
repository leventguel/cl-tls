(defpackage :asn1-extractors
  (:use :cl :shared-utils :asn1-types :asn1-schema :asn1-utils :asn1-parser :asn1-encoders)
  (:export :safe-getf :oid->name :extract-subject-fields :extract-public-key-info
	   :decode-time-string-raw :decode-time-string
	   :extract-validity-raw :extract-validity
	   :general-name-type
	   :extract-extension-block :extract-extensions
	   :decode-extension-value
	   :decode-general-names
	   :decode-subject-key-identifier :decode-authority-key-identifier :decode-basic-constraints
	   :extract-serial-number :extract-signature-algorithm
	   :extract-bit-string-sequence
	   :extract-element-bytes :extract-element-bytes-from-der
	   :extract-raw-tbs
	   :extract-printable-values))

(in-package :asn1-extractors)

(defun safe-getf (plist key)
  (if (and (listp plist) (member key plist :key #'car))
      (getf plist key)
      nil))

;; DER encoded bytes
(defun oid->name (oid-bytes)
  (cond
    ((equalp oid-bytes #(85 4 3)) 'CN)   ;; Common Name
    ((equalp oid-bytes #(85 4 10)) 'O)   ;; Organization
    ((equalp oid-bytes #(85 4 11)) 'OU)  ;; Organizational Unit
    ((equalp oid-bytes #(85 4 6)) 'C)    ;; Country
    ((equalp oid-bytes #(85 4 7)) 'L)    ;; Locality
    ((equalp oid-bytes #(85 4 8)) 'ST)   ;; State/Province
    ((equalp oid-bytes #(42 134 72 134 247 13 1 9 1)) "emailAddress") ;; emailAddress
    ((equalp oid-bytes #(42 134 72 134 247 13 1 1 1)) "RSA") ;; 1.2.840.113549.1.1.1
    ((equalp oid-bytes #(42 134 72 134 247 13 1 1 11)) "sha256WithRSAEncryption") ;; 1.2.840.113549.1.1.11
    ((equalp oid-bytes #(96 134 72 1 101 3 4 2 1)) "SHA-256") ;; 2.16.840.1.101.3.4.2.1
    ((equalp oid-bytes #(43 129 4 0 34)) "ECDSA")            ;; 1.3.132.0.34 (secp384r1)
    ((equalp oid-bytes #(85 29 14)) "subjectKeyIdentifier") ;; 2.5.29.14 → subjectKeyIdentifier
    ((equalp oid-bytes #(85 29 35)) "authorityKeyIdentifier") ;; 2.5.29.35 → authorityKeyIdentifier
    ((equalp oid-bytes #(85 29 19)) "basicConstraints") ;; 2.5.29.19 → basicConstraints
    ((equalp oid-bytes #(85 29 17)) "subjectAltName") ;; 2.5.29.17 → subjectAltName
    ((equalp oid-bytes #(85 29 15)) "keyUsage")
    ((equalp oid-bytes #(85 29 32)) "certificatePolicies")
    ((equalp oid-bytes #(85 29 31)) "CRLDistributionPoints")
    ((equalp oid-bytes #(85 29 30)) "nameConstraints")
    ((equalp oid-bytes #(85 29 37)) "extendedKeyUsage")
    ((equalp oid-bytes #(42 134 72 206 61 4 1)) "id-kp-serverAuth")
    ((equalp oid-bytes #(42 134 72 206 61 4 2)) "id-kp-clientAuth")
    ((equalp oid-bytes #(42 134 72 206 61 4 3)) "id-kp-codeSigning")
    ;; fallback: raw OID
    (t oid-bytes)))

(defun extract-subject-fields (subject-element)
  (loop for set in (getf subject-element :value)
        append
        (loop for attr in (getf set :value)
              collect
              (let* ((pair (getf attr :value))
                     (oid (getf (first pair) :value))
                     (value-bytes (getf (second pair) :value))
                     (value-str (map 'string #'code-char value-bytes)))
                (cons (oid->name oid) value-str)))))

(defun extract-public-key-info (spki-element)
  (let* ((spki-seq (getf spki-element :value))
         (algorithm (first spki-seq))
         (bit-string (second spki-seq))
         (alg-seq (getf algorithm :value))
         (oid (getf (first alg-seq) :value))
         (key-bytes (getf bit-string :value)))
    (list :algorithm (oid->name oid)
          :key-bytes key-bytes)))

(defun decode-time-string-raw (bytes)
  (map 'string #'code-char bytes))

(defun decode-time-string (bytes)
  (let ((str (map 'string #'code-char bytes)))
    (cond
      ;; UTCTime: YYMMDDhhmmssZ
      ((and (= (length str) 13) (char= (char str 12) #\Z))
       (let ((year (parse-integer (subseq str 0 2)))
             (month (parse-integer (subseq str 2 4)))
             (day (parse-integer (subseq str 4 6)))
             (hour (parse-integer (subseq str 6 8)))
             (minute (parse-integer (subseq str 8 10)))
             (second (parse-integer (subseq str 10 12))))
         (format nil "~D-~2,'0D-~2,'0D ~2,'0D:~2,'0D:~2,'0D UTC"
                 (+ 2000 (if (< year 50) year (+ year -100)))
                 month day hour minute second)))

      ;; GeneralizedTime: YYYYMMDDhhmmssZ
      ((and (>= (length str) 15) (char= (char str (1- (length str))) #\Z))
       (let ((year (parse-integer (subseq str 0 4)))
             (month (parse-integer (subseq str 4 6)))
             (day (parse-integer (subseq str 6 8)))
             (hour (parse-integer (subseq str 8 10)))
             (minute (parse-integer (subseq str 10 12)))
             (second (parse-integer (subseq str 12 14))))
         (format nil "~D-~2,'0D-~2,'0D ~2,'0D:~2,'0D:~2,'0D UTC"
                 year month day hour minute second)))

      ;; Fallback
      (t str))))

(defun extract-validity-raw (validity-element)
  (let ((times (getf validity-element :value)))
    (let ((not-before (getf (first times) :value))
          (not-after  (getf (second times) :value)))
      (list :not-before (decode-time-string-raw not-before)
            :not-after  (decode-time-string-raw not-after)))))

(defun extract-validity (validity-element)
  (let ((times (getf validity-element :value)))
    (let ((not-before (getf (first times) :value))
          (not-after  (getf (second times) :value)))
      (list :not-before (decode-time-string not-before)
            :not-after  (decode-time-string not-after)))))

(defun general-name-type (tag)
  (case tag
    (1 "Email Address")   ;; rfc822Name
    (2 "DNS Name")        ;; dNSName
    (7 "IP Address")      ;; iPAddress
    (t (format nil "Unknown (tag ~D)" tag))))

(defun extract-extensions-block (tbs)
  (let ((extensions-wrapper (nth 7 (getf tbs :value)))) ;; context-specific tag 3
    (when (and (eq (getf extensions-wrapper :class) :context-specific)
               (= (getf extensions-wrapper :tag) 3))
      (first (getf extensions-wrapper :value))))) ;; inner SEQUENCE

(defun extract-extensions (extensions-sequence)
  (loop for ext in (getf extensions-sequence :value)
        collect
        (let* ((fields (getf ext :value))
               (oid (getf (first fields) :value))
               (critical (if (= (length fields) 3)
                             (getf (second fields) :value)
                             nil))
               (octets (getf (nth (if critical 2 1) fields) :value)))
          (list :oid (oid->name oid)
                :critical critical
                :raw-value octets))))

(defun decode-extension-value (octets)
  (parse-asn1-element (make-byte-stream :data octets)))

(defun decode-general-names (asn1-seq)
  (loop for general-name in (getf asn1-seq :value)
        collect
        (let ((tag (getf general-name :tag))
              (value (map 'string #'code-char (getf general-name :value))))
          (list :type (general-name-type tag) :value value))))

(defun decode-subject-key-identifier (element)
  (list (list :type "Key Identifier"
              :value (byte-vector-to-hex-string (getf element :value)))))

(defun decode-authority-key-identifier (asn1-seq)
  (loop for element in (getf asn1-seq :value)
        collect
        (let ((tag (getf element :tag))
              (value (getf element :value)))
          (list :type (case tag
                        (0 "Key Identifier")
                        (1 "Cert Issuer")
                        (2 "Serial Number")
                        (t (format nil "Unknown (tag ~D)" tag)))
                :value (byte-vector-to-hex-string value)))))

(defun decode-basic-constraints (asn1-seq)
  (loop for field in (getf asn1-seq :value)
        collect
        (let ((tag (getf field :tag))
              (value (getf field :value)))
          (case tag
            (1 (list :type "CA" :value (if (equalp value #(255)) "TRUE" "FALSE")))
            (2 (list :type "Path Length" :value value))
            (t (list :type (format nil "Unknown (tag ~D)" tag) :value value))))))

(defun extract-serial-number (tbs)
  (let ((serial (nth 1 (getf tbs :value))))
    (getf serial :value)))

(defun extract-signature-algorithm (tbs)
  (let ((sig-algo (nth 2 (getf tbs :value))))
    (let ((fields (getf sig-algo :value)))
      (list :oid (oid->name (getf (first fields) :value))
            :params (if (second fields)
                        (getf (second fields) :value)
                        nil)))))

(defun extract-bit-string-sequence (bit-string)
  ;; Generic utility to decode a BIT STRING wrapping a SEQUENCE
  (parse-asn1-element (make-byte-stream :data (subseq bit-string 1))))

(defun extract-element-bytes (stream element &optional verbose-p)
  (let (;;(element-start (getf element :start-pos))
	;;(element-start (byte-stream-pos stream))
	(element-start 4)
	(element-length (getf element :total-length)))
    (when verbose-p
      (progn
	(format t "~%Element start  : ~A" element-start)
	(format t "~%Element length : ~A" element-length)))
    (subseq (byte-stream-data stream) element-start (+ element-start element-length))))

(defun extract-element-bytes-from-der (der-bytes element &optional verbose-p)
  (let ((start (getf element :start-pos))
        (length (getf element :total-length)))
    (when verbose-p
      (format t "~%Element start  : ~A" start)
      (format t "~%Element length : ~A" length))
    (subseq der-bytes start (+ start length))))

(defun extract-raw-tbs (cert-bytes parsed-cert)
  (let* ((tbs (first (getf parsed-cert :value)))
	 (tbs-start (+ (getf tbs :start-pos) 4))
	 (tbs-total-length (getf tbs :total-length)))
    (subseq cert-bytes tbs-start (+ tbs-start tbs-total-length))))

(defun extract-printable-values (element)
  (let ((results '()))
    (labels ((walk (node)
               (when (and (listp node)
                          (getf node :value)
                          (not (getf node :constructed)))
                 (let ((type (getf node :type))
                       (val (getf node :value)))
                   (when (and (member type '(:utf8-string :printable-string :ia5-string nil))
                              (vectorp val)
                              (every #'integerp val))
                     (handler-case
                         (push (decode-utf8 val) results)
                       (error () nil)))))
               (when (getf node :constructed)
                 (mapc #'walk (getf node :value)))))
      (walk element))
    (nreverse results)))
