;;;; cl-tls.asd
(asdf:defsystem #:cl-tls
    :description "Common Lisp TLS implementation"
    :author "Levent Guel"
    :license "MIT"
    :version "0.1"
    :depends-on (#:flexi-streams #:cl-json #:ironclad) ;; only needed for testing, none of that will be used internally
    :serial t
    :components (
		 ;; X509 Parser components
		 ;; ASN.1
		 (:file "x509-parser/asn1/asn1-types.lisp")
		 (:file "x509-parser/asn1/asn1-schema.lisp")
		 (:file "x509-parser/asn1/asn1-utils.lisp")
		 (:file "x509-parser/asn1/asn1-core.lisp")

		 ;; DER
		 (:file "x509-parser/der/der-utils.lisp")
		 (:file "x509-parser/der/der-parser.lisp")

		 ;; RSA
		 (:file "x509-parser/crypto/")

		 ;; X509
		 (:file "x509-parser/x509/x509-utils.lisp")
		 (:file "x509-parser/x509/x509-fields.lisp")
		 (:file "x509-parser/x509/x509-parser.lisp")
		 (:file "x509-parser/x509/x509-export.lisp")
		 ))
