(defpackage :asn1-types
  (:use :cl)
  (:export :*asn1-types*))

(defparameter *asn1-types*
  '((0 . :eoc)
    (1 . :boolean)
    (2 . :integer)
    (3 . :bit-string)
    (4 . :octet-string)
    (5 . :null)
    (6 . :object-id)
    (16 . :sequence)
    (17 . :set)
    ;; Add more as needed
    ))
