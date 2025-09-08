(load "/home/inline/quicklisp/setup.lisp")
(ql:quickload :cl-ppcre)
#.(require 'cl-ppcre)

(defpackage :der-utils
  (:use :cl)
  (:export :bigint-to-hex :integer-to-byte-array :bytes-to-string :string-match
	   :decode-bit-string :parse-object-id :reconstruct-der-element :cert-fingerprint))

(in-package :der-utils)

(defun bigint-to-hex (n)
  (format nil "~{~2,'0X~}" (coerce (integer-to-byte-array n) 'list)))

(defun integer-to-byte-array (n)
  "Convert integer to byte array (big-endian)."
  (let ((bytes '()))
    (loop while (> n 0) do
	  (push (mod n 256) bytes)
	  (setf n (floor n 256)))
    (make-array (length bytes) :element-type '(unsigned-byte 8) :initial-contents bytes)))

(defun bytes-to-string (vec)
  (map 'string #'code-char vec))

(defun string-match (pattern string)
  "Return true if PATTERN matches STRING using cl-ppcre."
  (cl-ppcre:scan pattern string))

(defun decode-bit-string (bit-string-element)
  "Extract raw bytes from BIT STRING element, skipping unused bits byte."
  (let ((raw (getf bit-string-element :raw)))
    (when (and raw (> (length raw) 1))
      (subseq raw 1))))

(defun parse-object-id (bytes)
  "Parse a DER-encoded OBJECT IDENTIFIER from a byte vector."
  (let ((tag (aref bytes 0)))
    (unless (= tag #x06)
      (error "Expected OBJECT IDENTIFIER tag"))
    (multiple-value-bind (length offset) (parse-der-length bytes 1)
      (let* ((oid-bytes (subseq bytes offset (+ offset length)))
             (first-byte (aref oid-bytes 0))
             (first (floor first-byte 40))
             (second (mod first-byte 40))
             (components (list first second))
             (value 0)
             (result '()))
        ;; Iterate over remaining bytes
        (loop for i from 1 below (length oid-bytes)
              for b = (aref oid-bytes i)
              do (setf value (+ (* value 128) (logand b #x7F)))
              (unless (logbitp 7 b)
                (push value result)
                (setf value 0)))
        (format nil "~{~A~^.~}" (append components (nreverse result)))))))

(defun reconstruct-der-element (tag raw-bytes)
  "Reconstruct full DER element from tag and raw bytes."
  (let* ((length (length raw-bytes))
         (length-encoding (if (< length #x80)
                              (vector length)
                              (let* ((len-bytes (loop for i from (1- (integer-length length)) downto 0
                                                      collect (ldb (byte 8 (* 8 i)) length)))
                                     (len-len (length len-bytes)))
                                (concatenate 'vector (vector (+ #x80 len-len)) (coerce len-bytes 'vector)))))
         (full (concatenate 'vector (vector tag) length-encoding raw-bytes)))
    full))

;; usage like (parse-der-sequence #(48 3 2 1 5)) i.e. Parses SEQUENCE of one INTEGER (5)

(defun cert-fingerprint (der-bytes &optional (algo :sha256))
  (let ((digest (ironclad:digest-sequence algo der-bytes)))
    (map 'string (lambda (b) (format nil "~2,'0X" b)) digest)))
