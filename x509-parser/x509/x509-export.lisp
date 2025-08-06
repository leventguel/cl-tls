(load "/home/inline/quicklisp/setup.lisp")
(ql:quickload :ironclad)
(ql:quickload :cl-json)
#.(require 'cl-json)

(defun cert-fingerprint (der-bytes &optional (algo :sha256))
  (let ((digest (ironclad:digest-sequence algo der-bytes)))
    (map 'string (lambda (b) (format nil "~2,'0X" b)) digest)))

(cl-json:encode-json-to-string *cert-structure*)
