(defpackage :des-base64
  (:use :cl)
  (:export :base64-encode :base64-decode :string-to-base64 :base64-to-string))

(in-package :des-base64)

(defparameter +base64-chars+
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")

(defun base64-encode (bytes)
  "Encode a byte vector into a Base64 string."
  (let ((output "")
        (pad 0))
    (declare (ignore pad))
    (loop for i from 0 below (length bytes) by 3
          for chunk = (subseq bytes i (min (+ i 3) (length bytes)))
          do (let* ((b1 (aref chunk 0))
                    (b2 (if (> (length chunk) 1) (aref chunk 1) 0))
                    (b3 (if (> (length chunk) 2) (aref chunk 2) 0))
                    (c1 (ash b1 -2))
                    (c2 (logior (ash (logand b1 3) 4) (ash b2 -4)))
                    (c3 (logior (ash (logand b2 15) 2) (ash b3 -6)))
                    (c4 (logand b3 63)))
               (setf output (concatenate 'string output
                                         (string (aref +base64-chars+ c1))
                                         (string (aref +base64-chars+ c2))
                                         (if (> (length chunk) 1)
                                             (string (aref +base64-chars+ c3))
                                             "=")
                                         (if (> (length chunk) 2)
                                             (string (aref +base64-chars+ c4))
                                             "=")))))
    output))

(defun base64-decode (str)
  "Decode a Base64 string into a byte vector."
  (let ((table (make-hash-table :test 'equal))
        output)
    ;; Build lookup table
    (loop for i from 0 below (length +base64-chars+)
          do (setf (gethash (char +base64-chars+ i) table) i))
    ;; Process input in chunks of 4
    (loop for i from 0 below (length str) by 4
          for c1 = (gethash (char str i) table)
          for c2 = (gethash (char str (+ i 1)) table)
          for c3-char = (char str (+ i 2))
          for c4-char = (char str (+ i 3))
          for c3 = (gethash c3-char table)
          for c4 = (gethash c4-char table)
          do (let ((b1 (logior (ash c1 2) (ash c2 -4))))
               (push b1 output)
               (unless (char= c3-char #\=)
                 (let ((b2 (logior (ash (logand c2 15) 4) (ash c3 -2))))
                   (push b2 output)))
               (unless (char= c4-char #\=)
                 (let ((b3 (logior (ash (logand c3 3) 6) c4)))
                   (push b3 output)))))
    (coerce (nreverse output) 'vector)))

(defun string-to-base64 (str)
  (base64-encode
   (map 'vector #'char-code str))) ; UTF-8-ish, assuming ASCII

(defun base64-to-string (b64)
  (map 'string #'code-char
       (base64-decode b64)))
