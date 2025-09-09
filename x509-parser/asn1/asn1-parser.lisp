(defpackage :asn1-parser
  (:use :cl :asn1-types :asn1-schema :asn1-utils)
  (:export :asn1-tag-class :asn1-constructed-p
	   :read-file-as-byte-stream :decode-length :decode-length-info :decode-tag
	   :parse-asn1-sequence :parse-asn1-element
	   :print-asn1-tree))

(in-package :asn1-parser)

(defun asn1-tag-class (tag)
  (case (ldb (byte 2 6) tag)
    (0 :universal)
    (1 :application)
    (2 :context-specific)
    (3 :private)))

(defun asn1-constructed-p (tag)
  (logbitp 5 tag)) ; bit 6 (zero-indexed)

(defun read-file-as-byte-stream (path)
  (with-open-file (s path :element-type '(unsigned-byte 8))
    (let ((data (make-array (file-length s) :element-type '(unsigned-byte 8))))
      (read-sequence data s)
      (make-byte-stream :data data :pos 0))))

(defun decode-length-info (stream)
  (let ((mystream stream))
  (let ((first-byte (read-byte-from-any mystream)))
    (if (< first-byte 128)
        ;; Short form: length is in first byte
        (list :value-length first-byte
              :length-bytes 1)
        ;; Long form: first byte tells how many bytes follow
        (let ((num-bytes (- first-byte 128))
              (acc 0))
          (dotimes (i num-bytes)
            (setf acc (+ (* acc 256) (read-byte-from-any mystream))))
          (list :value-length acc
                :length-bytes (1+ num-bytes)))))))

(defun decode-tag (tag-byte &optional verbose-p)
  (unless tag-byte
    (error "decode-tag called with NIL — stream likely exhausted"))
  (let ((class (asn1-tag-class tag-byte))
        (constructed (asn1-constructed-p tag-byte))
        (tag-number (ldb (byte 5 0) tag-byte))) ; bits 0–4
    (when verbose-p
      (format t "~%[DECODE-TAG] Byte: ~A → Class: ~A, Constructed: ~A, Tag #: ~A"
              tag-byte class constructed tag-number))
    (list :class class :constructed constructed :tag tag-number)))

(declaim (ftype function parse-asn1-element))

(defun parse-asn1-sequence (stream &optional (absolute-offset 0))
  (let ((elements nil))
    (loop while (peek-byte-from-any stream)
          do (push (parse-asn1-element stream absolute-offset) elements))
    (nreverse elements)))

(defun parse-asn1-element (stream &optional (absolute-offset 0))
  (let ((start-pos (+ absolute-offset (byte-stream-pos stream))))
	;;(start-pos (+ absolute-offset 0)))
    (let* ((tag-byte (read-byte-from-any stream))
           (tag-info (decode-tag tag-byte))
           (length-info (decode-length-info stream))
           (value-length (getf length-info :value-length))
           (length-bytes (getf length-info :length-bytes))
	   (header-length (+ 1 length-bytes)) ;; tag + length
           (value-bytes (make-array value-length :element-type '(unsigned-byte 8))))

	(dotimes (i value-length)
          (setf (aref value-bytes i) (read-byte-from-any stream)))
	
      (let ((type (if (eq (getf tag-info :class) :universal)
                      (cdr (assoc (getf tag-info :tag) *asn1-types*))
                      nil)))
	(list :type type
              :class (getf tag-info :class)
              :constructed (getf tag-info :constructed)
              :tag (getf tag-info :tag)
              :length value-length
              :total-length (+ 1 length-bytes value-length) ; tag + length + value
              :start-pos start-pos
	      :offset absolute-offset
              :value (if (getf tag-info :constructed)
			 (parse-asn1-sequence
			  (make-byte-stream :data value-bytes :pos 0)
			  (+ start-pos absolute-offset header-length))
			 value-bytes))))))

(defun parse-asn1-sequence (stream)
  (let ((elements nil))
    (loop while (peek-byte-from-any stream)
          do (push (parse-asn1-element stream) elements))
    (nreverse elements)))

(defun parse-asn1-element (stream)
  (let ((start-pos (byte-stream-pos stream)))
	;;(start-pos (+ absolute-offset 0)))
	;;(start-pos 0))
    (let* ((tag-byte (read-byte-from-any stream))
           (tag-info (decode-tag tag-byte))
           (length-info (decode-length-info stream))
           (value-length (getf length-info :value-length))
           (length-bytes (getf length-info :length-bytes))
	   (header-length (+ 1 length-bytes)) ;; tag + length
           (value-bytes (make-array value-length :element-type '(unsigned-byte 8))))
      (dotimes (i value-length)
        (setf (aref value-bytes i) (read-byte-from-any stream)))
      (let ((type (if (eq (getf tag-info :class) :universal)
		      (cdr (assoc (getf tag-info :tag) *asn1-types*))
		      nil)))
	(list :type type
              :class (getf tag-info :class)
              :constructed (getf tag-info :constructed)
              :tag (getf tag-info :tag)
              :length value-length
	      :header-length header-length
              :total-length (+ header-length value-length) ; tag + value
              :start-pos start-pos
              :value (if (getf tag-info :constructed)
			 (parse-asn1-sequence
			  (make-byte-stream :data value-bytes :pos 0))
			 value-bytes))))))

(defun print-asn1-tree (element &optional (indent 0))
  (format t "~&~v@T~A~%" indent (getf element :type))
  (when (getf element :constructed)
    (dolist (child (getf element :value))
      (print-asn1-tree child (+ indent 2)))))
