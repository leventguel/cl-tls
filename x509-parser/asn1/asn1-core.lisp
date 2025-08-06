(defpackage :asn1
  (:use :cl :asn1-types :asn1-schema :asn1-utils)
  (:export :make-byte-stream-from-bytes :asn1-tag-class :asn1-constructed-p
	   :read-der-file-as-bytestream :decode-length :decode-tag
	   :parse-asn1-sequence :parse-asn1-element
	   :extract-printable-values :print-asn1-tree))

(defstruct byte-stream
  data
  (pos 0))

(defun make-byte-stream-from-bytes (byte-array)
  (make-byte-stream :data byte-array))

(defun asn1-tag-class (tag)
  (case (ldb (byte 2 6) tag)
    (0 :universal)
    (1 :application)
    (2 :context-specific)
    (3 :private)))

(defun asn1-constructed-p (tag)
  (logbitp 5 tag)) ; bit 6 (zero-indexed)

(defun read-der-file-as-byte-stream (path)
  (with-open-file (s path :element-type '(unsigned-byte 8))
    (let ((data (make-array (file-length s) :element-type '(unsigned-byte 8))))
      (read-sequence data s)
      (make-byte-stream-from-bytes data))))

(defun decode-length (stream)
  (let ((first-byte (read-byte-from-any stream)))
    (if (< first-byte 128)
        first-byte
        (let ((num-bytes (- first-byte 128)))
          (loop repeat num-bytes
                for b = (read-byte-from-any stream)
                for acc = b then (+ (* acc 256) b)
                finally (return acc))))))

(defun decode-tag (tag-byte)
  (let ((class (asn1-tag-class tag-byte))
        (constructed (asn1-constructed-p tag-byte))
        (tag-number (ldb (byte 5 0) tag-byte))) ; bits 0–4
    (list :class class :constructed constructed :tag tag-number)))

(defun parse-asn1-sequence (stream)
  (let ((elements '()))
    (loop while (peek-byte-from-any stream)
          do (push (parse-asn1-element stream) elements))
    (nreverse elements)))

(defun parse-asn1-element (stream)
  (let* ((tag-byte (read-byte-from-any stream))
         (tag-info (decode-tag tag-byte))
         (length (decode-length stream))
         (value-bytes (make-array length :element-type '(unsigned-byte 8))))
    (dotimes (i length)
      (setf (aref value-bytes i) (read-byte-from-any stream)))
    (let ((type (cdr (assoc (getf tag-info :tag) *asn1-types*))))
      (list :type type
            :class (getf tag-info :class)
            :constructed (getf tag-info :constructed)
            :length length
            :value (if (getf tag-info :constructed)
                       (parse-asn1-sequence (make-byte-stream-from-bytes value-bytes))
                       value-bytes)))))

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

(defun print-asn1-tree (element &optional (indent 0))
  (format t "~&~v@T~A~%" indent (getf element :type))
  (when (getf element :constructed)
    (dolist (child (getf element :value))
      (print-asn1-tree child (+ indent 2)))))
