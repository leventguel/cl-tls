(defpackage :asn1-encoders
  (:use :cl
	:shared-utils :asn1-utils :asn1-parser
	:sha1 :sha224 :sha256 :sha384 :sha512
	:hmac-sha1 :hmac-sha224 :hmac-sha256 :hmac-sha384 :hmac-sha512)
  (:export :encode-length :encode-integer :encode-sequence :encode-octet-string :encode-bit-string
	   :encode-oid-subid :encode-object-identifier :encode-null :encode-digest-info
	   :build-digest-info
	   :encode-pkcs1-v1.5 :encode-tag-byte :encode-asn1-value :encode-asn1-element
	   :test-encode-sequence :test-encode-object :test-encode-digest))

(in-package :asn1-encoders)

(defun encode-length (len)
  (if (< len 128)
      (vector len)
      (let ((len-bytes (integer-to-byte-vector len)))
        (concatenate 'vector
                     (vector (+ 128 (length len-bytes)))
                     len-bytes))))

(defun encode-integer (n)
  (let* ((bytes (integer-to-byte-vector n))
         (padded (if (>= (aref bytes 0) 128)
                     (concatenate 'vector #(0) bytes)
                     bytes))
         (length (length padded)))
    (concatenate 'vector
                 #(2) ;; INTEGER tag
                 (encode-length length)
                 padded)))

(defun encode-sequence (&rest elements)
  (let* ((body (apply #'concatenate 'vector elements))
         (length (length body)))
    (concatenate 'vector
                 #(48) ;; SEQUENCE tag
                 (encode-length length)
                 body)))

(defun encode-octet-string (bytes)
  (concatenate 'vector
               #(4) ;; OCTET STRING tag
               (encode-length (length bytes))
               bytes))

(defun encode-bit-string (bytes &optional (unused-bits 0))
  (let ((payload (concatenate 'vector (vector unused-bits) bytes)))
    (concatenate 'vector
                 #(3) ;; BIT STRING tag
                 (encode-length (length payload))
                 payload)))

(defun encode-oid-subid (n)
  "Encodes a single OID sub-identifier using base-128 encoding."
  (if (< n 128)
      (list n)
      (let ((bytes '()))
        (loop
          (push (logand n #x7F) bytes)
          (setf n (ash n -7))
          (when (zerop n) (return)))
        ;; Set MSB on all but last
        (mapcar #'(lambda (b) (logior b #x80)) (butlast bytes))
        ;; Last byte has MSB = 0
        (append (mapcar #'(lambda (b) (logior b #x80)) (butlast bytes))
                (list (car (last bytes)))))))

(defun encode-object-identifier (oid-list)
  (let ((first-byte (+ (* 40 (first oid-list)) (second oid-list)))
        (rest-bytes (mapcan #'encode-oid-subid (cddr oid-list))))
    (concatenate 'vector
                 #(6) ;; OBJECT IDENTIFIER tag
                 (encode-length (1+ (length rest-bytes)))
                 (vector first-byte)
                 (coerce rest-bytes 'vector))))

(defun encode-null ()
  ;; NULL tag + zero-length
  #(5 0))

;; Dotted decimal oids
(defun encode-digest-info (hash &optional (algorithm-oid '(2 16 840 1 101 3 4 2 1))) ;; SHA-256
  (let* ((alg-id (encode-sequence
                   (encode-object-identifier algorithm-oid)
                   (encode-null)))
         (digest (encode-octet-string hash)))
    (encode-sequence alg-id digest)))

(defun build-digest-info (hash)
  "Constructs a DER-encoded DigestInfo structure for SHA-256 as per RFC 8017."
  (let* ((sha256-oid '(2 16 840 1 101 3 4 2 1)) ; SHA-256 OID in dotted-decimal
         (algo-id (encode-sequence
                   (encode-object-identifier sha256-oid)
                   (encode-null)))
         (digest (encode-octet-string hash)))
    (encode-sequence algo-id digest)))

;; Padding encoder
(defun encode-pkcs1-v1.5 (digest-info-bytes modulus-size)
  (let* ((digest-len (length digest-info-bytes))
         (ps-len (- modulus-size digest-len 3))) ;; 3 = #x00 #x01 #x00
    (if (< ps-len 8)
        (error "PKCS#1 v1.5 padding too short")
        (concatenate 'vector
                     #(0 1) ;; #x00 #x01
                     (make-array ps-len :initial-element 255) ;; PS = #xFF
                     #(0) ;; separator
                     digest-info-bytes))))

(defun encode-tag-byte (tag class constructed)
  (let ((class-bits (case class
                      (:universal 0)
                      (:application 64)
                      (:context-specific 128)
                      (:private 192)))
        (pc-bit (if constructed 32 0)))
    (vector (+ class-bits pc-bit tag))))

(declaim (ftype function encode-asn1-element))

(defun encode-asn1-value (value constructed)
  (cond
    (constructed
     ;; Assume value is a list of ASN.1 elements
     (apply #'concatenate 'vector
            (mapcar #'encode-asn1-element value)))
    ((typep value '(vector (unsigned-byte 8)))
     ;; Raw byte vector
     value)
    ((stringp value)
     ;; Encode string as UTF-8 bytes
     (map 'vector #'char-code value))
    ((integerp value)
     ;; Encode integer using minimal representation
     (encode-integer value))
    (t
     (error "Unsupported ASN.1 value type: ~A" (type-of value)))))

(defun encode-asn1-element (element)
  (let* ((tag (getf element :tag))
         (class (getf element :class))
         (constructed (getf element :constructed))
         (value (getf element :value))
         (tag-byte (encode-tag-byte tag class constructed))
         (encoded-value (encode-asn1-value value constructed))
         (length-bytes (encode-length (length encoded-value))))
    (concatenate 'vector tag-byte length-bytes encoded-value)))

(defun test-encode-sequence ()
  (encode-sequence
   (encode-integer 65537)
   (encode-integer 123456789)))

(defun test-encode-object ()
  ;; sha256WithRSAEncryption
  (encode-object-identifier '(1 2 840 113549 1 1 11)))

(defun test-encode-digest (some-bytes)
  (let ((hash (sha256 some-bytes)))
    (encode-digest-info hash)))
