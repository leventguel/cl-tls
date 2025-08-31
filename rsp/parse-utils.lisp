(defpackage :parse-utils
  (:use :cl)
  (:export :bracketed-line-p :starts-with))

(in-package :parse-utils)

(defun bracketed-line-p (line)
  "Returns true if line starts with [ and ends with ]."
  (and (> (length line) 2)
       (char= (char line 0) #\[)
       (char= (char line (1- (length line))) #\])))

(defun starts-with (prefix string)
  "Returns T if STRING starts with PREFIX."
  (and (<= (length prefix) (length string))
       (string= prefix (subseq string 0 (length prefix)))))
