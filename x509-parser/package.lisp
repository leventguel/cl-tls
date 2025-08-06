;; package.lisp
(defpackage :asn1
  (:use :cl)
  (:export :parse-der-sequence :parse-der-element :der-tag-type ...))

(defpackage :der-utils
  (:use :cl)
  (:export :parse-der-sequence :parse-der-element :der-tag-type ...))

(defpackage :der-parser
  (:use :cl :der-utils)
  (:export :parse-der-sequence :parse-der-element :der-tag-type ...))

(defpackage :der
  (:use :cl :der-utils :der-parser)
  (:export :parse-der-sequence :parse-der-element :der-tag-type ...))

(defpackage :x509
  (:use :cl :asn1)
  (:export :parse-x509-certificate :extract-subject-fields ...))

(defpackage :crypto
  (:use :cl :asn1)
  (:export :extract-rsa-public-key :verify-signature ...))

(defpackage :x509-core
  (:use :cl :der-utils)
  (:export :parse-x509-certificate :extract-subject :extract-public-key ...))

(defpackage :x509-cli
  (:use :cl :x509-core)
  (:export :pretty-print-cert :dump-fields :interactive-inspect))
