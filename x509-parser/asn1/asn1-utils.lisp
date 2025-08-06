(load "/home/inline/quicklisp/setup.lisp")
(ql:quickload :flexi-streams)

(defpackage :asn1-utils
  (:use :cl :asn1-types :asn1-schema)
  (:export :decode-utf8 :byte-stream-read-byte :byte-stream-peek-byte
	   :read-byte-from-any :peek-byte-from-any))

(defun decode-utf8 (bytes)
  (handler-case
      (flexi-streams:octets-to-string bytes :external-format :utf-8)
    (flexi-streams:external-format-encoding-error ()
      (flexi-streams:octets-to-string bytes :external-format :latin-1))))

(defun byte-stream-read-byte (stream)
  (let ((pos (byte-stream-pos stream))
        (data (byte-stream-data stream)))
    (if (>= pos (length data))
        nil
        (prog1 (aref data pos)
          (setf (byte-stream-pos stream) (1+ pos))))))

(defun byte-stream-peek-byte (stream)
  (let ((pos (byte-stream-pos stream))
        (data (byte-stream-data stream)))
    (if (>= pos (length data))
        nil
        (aref data pos))))

(defun read-byte-from-any (stream)
  (typecase stream
    (byte-stream (byte-stream-read-byte stream))
    (stream (read-byte stream))))

(defun peek-byte-from-any (stream)
  (typecase stream
    (byte-stream (byte-stream-peek-byte stream))
    (stream (peek-char nil stream nil nil))))
