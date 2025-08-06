(defpackage :der-parser
  (:use :cl :der-utils)
  (:export :read-der-file :*server-der* :*cert-structure* :*spki-structure* :*pubkey-bitstring* :*pubkey-bytes*
	   :*rsa-key* :*oid-map* :parse-der-integer :parse-der-length :parse-der-sequence :parse-der-element
	   :parse-time :maybe-decode-oid :decode-attribute-pair :find-subject-cn
	   :der-tag-type :oid->name :context-specific-constructed-p :pretty-print-der-raw :pretty-print-der
	   :extract-rsa-public-key :find-subject-public-key-info))

(defun read-der-file (path)
  "Read a binary DER file into a vector of bytes."
  (with-open-file (stream path :element-type '(unsigned-byte 8) :direction :input)
    (let ((bytes (make-array (file-length stream) :element-type '(unsigned-byte 8))))
      (read-sequence bytes stream)
      bytes)))

(defparameter *server-der* (read-der-file "/home/inline/clocc/src/ssl/server.der"))
(defparameter *cert-structure* (parse-der-sequence *server-der*))
(defparameter *spki-structure* (find-subject-public-key-info *cert-structure*))
(defparameter *pubkey-bitstring* (second *spki-structure*))
(defparameter *pubkey-bytes* (decode-bit-string *pubkey-bitstring*))
(defparameter *rsa-key* (parse-der-sequence *pubkey-bytes*))

(defparameter *oid-map*
  '(("2.5.4.3" . "CN")
    ("2.5.4.6" . "C")
    ("2.5.4.7" . "L")
    ("2.5.4.8" . "ST")
    ("2.5.4.10" . "O")
    ("2.5.4.11" . "OU")
    ("1.2.840.113549.1.1.11" . "sha256WithRSAEncryption")
    ("1.2.840.113549.1.1.1" . "rsaEncryption")
    ;; Add more as needed
    ))

(defun parse-der-integer (bytes)
  "Parse a DER-encoded INTEGER from a byte vector."
  (let ((tag (aref bytes 0)))
    (unless (= tag #x02)
      (error "Expected INTEGER tag"))
    (let ((len-byte (aref bytes 1))
          (offset 2))
      (let ((length (if (< len-byte #x80)
                        len-byte
                        (let ((num-bytes (- len-byte #x80)))
                          (reduce (lambda (acc b)
                                    (+ (* acc 256) b))
                                  (subseq bytes offset (+ offset num-bytes))
                                  :initial-value 0)))))
        (let ((value-bytes (subseq bytes (+ offset (if (< len-byte #x80) 0 (- len-byte #x80)))
                                   (+ offset (if (< len-byte #x80) 0 (- len-byte #x80)) length))))
          ;; Convert to integer
          (reduce (lambda (acc b) (+ (* acc 256) b)) value-bytes :initial-value 0))))))

(defun parse-der-length (bytes offset)
  "Parse DER length starting at offset. Returns (length . new-offset)."
  (let ((len-byte (aref bytes offset)))
    (if (< len-byte #x80)
        ;; Short form
        (values len-byte (1+ offset))
        ;; Long form
        (let ((num-bytes (- len-byte #x80)))
          (let ((length (reduce (lambda (acc b) (+ (* acc 256) b))
                                (subseq bytes (1+ offset) (+ 1 offset num-bytes))
                                :initial-value 0)))
            (values length (+ 1 offset num-bytes)))))))

(defun parse-der-sequence (bytes)
  "Parse a DER-encoded SEQUENCE and return a list of parsed elements."
  (let ((tag (aref bytes 0)))
    (unless (= tag #x30)
      (error "Expected SEQUENCE tag"))
    (multiple-value-bind (length offset) (parse-der-length bytes 1)
      (let ((end (+ offset length))
            (elements nil))
        (loop while (< offset end) do
              (multiple-value-bind (element new-offset)
		  (parse-der-element bytes offset)
		(push element elements)
		(setf offset new-offset)))
        (nreverse elements)))))

;; Recursive
(defun parse-der-element (bytes offset)
  "Parse a single DER element starting at offset. Returns (value . new-offset)."
  (let ((tag (aref bytes offset)))
    (multiple-value-bind (length new-offset) (parse-der-length bytes (1+ offset))
      (let ((value-bytes (subseq bytes new-offset (+ new-offset length))))
        (cond
          ((= tag #x02) ;; INTEGER
           (values (reduce (lambda (acc b) (+ (* acc 256) b)) value-bytes :initial-value 0)
                   (+ new-offset length)))
          ((= tag #x30) ;; SEQUENCE
           (values (parse-der-sequence (subseq bytes offset (+ new-offset length)))
                   (+ new-offset length)))
          (t
           (values (list :unknown-tag tag :raw value-bytes)
                   (+ new-offset length))))))))

(defun parse-time (time-node)
  (let ((raw (second time-node))) ;; assuming (tag . value)
    (cond
      ((string-match "^\\d{12}Z$" raw) ;; UTCTime
       (format nil "~A-~A-~A ~A:~A:~A UTC"
               (subseq raw 0 2) (subseq raw 2 4) (subseq raw 4 6)
               (subseq raw 6 8) (subseq raw 8 10) (subseq raw 10 12)))
      ((string-match "^\\d{14}Z$" raw) ;; GeneralizedTime
       (format nil "~A-~A-~A ~A:~A:~A UTC"
               (subseq raw 0 4) (subseq raw 4 6) (subseq raw 6 8)
               (subseq raw 8 10) (subseq raw 10 12) (subseq raw 12 14)))
      (t raw))))

(defun maybe-decode-oid (obj)
  (when (and (listp obj)
             (eq (first obj) 'UNKNOWN-TAG)
             (= (second obj) 6)
             (eq (third obj) 'RAW)
             (listp (fourth obj))
             (eq (first (fourth obj)) 'RAW)
             (vectorp (second (fourth obj))))
    (let* ((bytes (second (fourth obj)))
           (oid (parse-object-id bytes))
           (name (oid->name oid)))
      (format nil "OID ~A (~A)" oid name))))

(defun decode-attribute-pair (obj)
  (when (and (listp obj)
             (eq (first obj) 'RAW)
             (vectorp (second obj)))
    (let ((parsed (parse-der-sequence (second obj))))
      (when (and (listp parsed)
                 (= (length parsed) 2))
        (let* ((oid-part (first parsed))
               (value-part (second parsed)))
          (when (and (eq (first oid-part) :unknown-tag)
                     (= (second oid-part) #x06)) ;; OID tag
            (let* ((oid-bytes (reconstruct-der-element #x06 (getf oid-part :raw)))
                   (oid (parse-object-id oid-bytes))
                   (name (oid->name oid))
                   (value-bytes (getf value-part :raw)))
              (format nil "~A: ~A" name (bytes-to-string value-bytes)))))))))

(defun find-subject-cn (cert)
  (some (lambda (entry)
          (and (listp entry)
               (some (lambda (subentry)
                       (and (listp subentry)
                            (equal (getf subentry :oid) "2.5.4.3")
                            (getf subentry :value)))
                     entry)))
        cert))

(defun der-tag-type (tag)
  (case tag
    (#x30 :sequence)
    (#x31 :set)
    (#x02 :integer)
    (#x06 :object-id)
    (#x13 :printable-string)
    (#x0C :utf8-string)
    (#x17 :utc-time)
    (#x16 :ia5-string)
    (#x05 :null)
    (#x03 :bit-string)
    (t :unknown)))

(defun oid->name (oid)
  (or (cdr (assoc oid *oid-map* :test #'string=)) oid))

(defun context-specific-constructed-p (tag)
  (and (>= tag #xA0) (<= tag #xBF)))

(defun pretty-print-der-raw (obj &optional (indent 0))
  (let ((prefix (make-string indent :initial-element #\Space)))
    (cond
      ((listp obj)
       (format t "~%~A(" prefix)
       (dolist (item obj)
         (pretty-print-der item (+ indent 2)))
       (format t "~%~A)" prefix))
      ((vectorp obj)
       (format t "~%~A#(" prefix)
       (dotimes (i (length obj))
         (pretty-print-der (aref obj i) (+ indent 2)))
       (format t "~%~A)" prefix))
      ((stringp obj)
       (format t "~%~A~S" prefix obj))
      ((symbolp obj)
       (format t "~%~A~A" prefix obj))
      (t
       (format t "~%~A~A" prefix obj)))))

(defun pretty-print-der (obj &optional (indent 0))
  (let ((prefix (make-string indent :initial-element #\Space)))
    (cond
      ;; Try decoding attribute pair
      ((let ((decoded (decode-attribute-pair obj)))
         (when decoded
           (format t "~%~A~A" prefix decoded)
           t)))

      ;; RAW vector: parse recursively
      ((and (listp obj)
            (eq (first obj) 'RAW)
            (vectorp (second obj)))
       (let ((parsed (parse-der-sequence (second obj))))
         (pretty-print-der parsed indent)))

      ;; context specifics
      ((and (listp obj)
	    (eq (first obj) :unknown-tag)
	    (vectorp (getf obj :raw))
	    (context-specific-constructed-p (second obj)))
       (format t "~%~A[Context-specific Tag ~A]" prefix (second obj))
       (multiple-value-bind (parsed _) (parse-der-element (getf obj :raw) 0)
	 (declare (ignore _))
	 (pretty-print-der parsed (+ indent 2))))
      
      ;; Tagged RAW: unwrap and parse
      ((and (listp obj)
	    (eq (first obj) :unknown-tag)
	    (vectorp (getf obj :raw)))
       (let* ((tag (second obj))
              (raw (getf obj :raw))
              (type (der-tag-type tag)))
	 (format t "~%~A[Tag ~A]" prefix tag)
	 (case type
	   (:sequence
	    (let ((parsed (parse-der-sequence raw)))
              (pretty-print-der parsed (+ indent 2))))
	   (:set
	    (let ((parsed (parse-der-sequence raw)))
	      (pretty-print-der parsed (+ indent 2))))
	   (:ia5-string
	    (format t "~%~AIA5String: ~A" prefix (bytes-to-string raw)))
	   (:object-id
	    (format t "~%~AOID: ~A" prefix (parse-object-id (reconstruct-der-element tag raw))))
	   (:integer
	    (format t "~%~AINTEGER: ~A" prefix (parse-der-integer (reconstruct-der-element tag raw))))
	   (:bit-string
	    (format t "~%~ABIT STRING: ~S" prefix raw))
	   (:utf8-string
	    (format t "~%~AUTF8String: ~A" prefix (bytes-to-string raw)))
	   (:printable-string
	    (format t "~%~APrintableString: ~A" prefix (bytes-to-string raw)))
	   (:utc-time
	    (format t "~%~AUTCTime: ~A" prefix (bytes-to-string raw)))
	   (:null
	    (format t "~%~ANULL" prefix))
	   (otherwise
	    (format t "~%~AUnknown tag ~A: ~S" prefix tag raw)))))
      ((listp obj)
       (format t "~%~A(" prefix)
       (dolist (item obj)
	 (pretty-print-der item (+ indent 2)))
       (format t "~%~A)" prefix)))))

(defun extract-rsa-public-key (cert-structure)
  "Extract RSA modulus and exponent from parsed certificate structure."
  (let* ((spki-entry (find-if (lambda (e)
                                (and (listp e)
                                     (some (lambda (x)
                                             (and (listp x)
                                                  (equal (car x) :unknown-tag)))
                                           e)))
                              cert-structure))
         (bitstring (and spki-entry (second spki-entry)))
         (pubkey-bytes (decode-bit-string bitstring)))
    (if pubkey-bytes
        (parse-der-sequence pubkey-bytes)
        (error "Could not extract public key bitstring"))))

(defun find-subject-public-key-info (cert-structure)
  "Find the subjectPublicKeyInfo SEQUENCE inside the parsed certificate."
  (let ((tbs-cert (first cert-structure)))
    ;; Look for a sublist that contains a BIT STRING (tag 3)
    (find-if (lambda (element)
               (and (listp element)
                    (some (lambda (sub)
                            (and (listp sub)
                                 (eq (car sub) :unknown-tag)
                                 (= (second sub) 3))) ;; BIT STRING tag
                          element)))
             tbs-cert)))

(format t "Modulus in Hex: ~a~%" (bigint-to-hex (car *rsa-key*))) ;; Modulus in hex
