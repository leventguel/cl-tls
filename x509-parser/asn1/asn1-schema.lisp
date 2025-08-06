(defpackage :asn1-schema
  (:use :cl)
  (:export :*certificate-schema*))

(defparameter *certificate-schema*
  '(:sequence
    (:context-specific 0 :integer) ; version
    :integer                      ; serial
    (:sequence :object-id :null)  ; signature algorithm
    :sequence                     ; issuer
    :sequence                     ; validity
    :sequence                     ; subject
    :sequence                     ; subjectPublicKeyInfo
    (:context-specific 3 :sequence))) ; extensions
