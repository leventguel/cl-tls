(load "/home/inline/quicklisp/setup.lisp")
(ql:quickload :cl-ppcre)
#.(require 'cl-ppcre)

(defpackage :der-utils
  (:use :cl)
  (:export :integer-to-byte-array :bigint-to-hex :bytes-to-string :string-match
	   :decode-bit-string :reconstruct-der-element :cert-fingerprint))

(in-package :der-utils)

(defun integer-to-byte-array (n)
  "Convert integer to byte array (big-endian)."
  (let ((bytes '()))
    (loop while (> n 0) do
	  (push (mod n 256) bytes)
	  (setf n (floor n 256)))
    (make-array (length bytes) :element-type '(unsigned-byte 8) :initial-contents bytes)))

(defun bigint-to-hex (n)
  (format nil "~{~2,'0X~}" (coerce (integer-to-byte-array n) 'list)))

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
    (with-output-to-string (out)
      (loop for b across digest
            do (format out "~2,'0X" b)))))
