(defpackage :asn1-schema
  (:use :cl)
  (:export :*certificate-schema* :*full-certificate-schema*
	   :match-sequence :match-schema))

(in-package :asn1-schema)

(defparameter *certificate-schema*
  '(:sequence
    (:context-specific 0 (:sequence :integer)) ;; version
    :integer                                   ;; serial
    (:sequence :object-id :null)               ;; signature algorithm
    :sequence                                  ;; issuer
    :sequence                                  ;; validity
    :sequence                                  ;; subject
    :sequence                                  ;; subjectPublicKeyInfo
    (:context-specific 3 :sequence)))          ;; extensions

(defparameter *full-certificate-schema*
  '(:sequence
    (:sequence ;; TBSCertificate
     (:context-specific 0 (:sequence :integer))
     :integer
     (:sequence :object-id :null)
     :sequence ;; issuer
     :sequence ; validity
     :sequence ;; subject
     :sequence ;; subjectPublicKeyInfo
     (:context-specific 3 :sequence))
    (:sequence :object-id :null) ;; signatureAlgorithm
    :bit-string)) ;; signatureValue

(defun match-sequence (elements schema depth)
  (if (/= (length elements) (length schema))
      (progn
        (format t "~%❌ Length mismatch: ~D elements vs ~D schema entries" (length elements) (length schema))
        nil)
      (loop for e in elements
            for s in schema
            for i from 0
            do (format t "~%[MATCH @~D] Element: ~A | Schema: ~A" i (getf e :type) s)
               (unless (match-schema e s depth)
                 (format t "~%❌ Mismatch at index ~D" i)
                 (return nil))
            finally (return t))))

(defun match-schema (element schema &optional (depth 0))
  (format t "~%[MATCH] ~v@TType: ~A | Class: ~A | Tag: ~A | Schema: ~A"
          (* depth 2)
          (getf element :type)
          (getf element :class)
          (getf element :tag)
          schema)
  (cond
    ;; Empty schema always matches
    ((null schema) t)

    ;; No element to match against
    ((null element) nil)

    ;; Schema expects a SEQUENCE
    ((and (listp schema) (eq (first schema) :sequence))
     (and (eq (getf element :type) :sequence)
          (match-sequence (getf element :value) (rest schema) (1+ depth))))

    ;; Schema expects a specific universal type
    ((symbolp schema)
     (eq (getf element :type) schema))

    ;; Schema expects a context-specific tag
    ((and (listp schema) (eq (first schema) :context-specific))
     (and (eq (getf element :class) :context-specific)
          (eq (getf element :tag) (second schema))
          (let ((inner (getf element :value))
                (subschema (third schema)))
            (cond
              ;; If schema expects a sequence, wrap inner in a synthetic SEQUENCE
              ((and (listp subschema)
                    (eq (first subschema) :sequence)
                    (listp inner))
               (match-schema
                (list :type :sequence
                      :class :universal
                      :constructed t
                      :tag 16
                      :value inner)
                subschema
                (1+ depth)))

              ;; If inner is a single plist, match directly
              ((and (listp inner)
                    (member :type inner))
               (match-schema inner subschema (1+ depth)))

              ;; If inner is a list of one plist, unwrap and match
              ((and (listp inner)
                    (= (length inner) 1)
                    (listp (first inner)))
               (match-schema (first inner) subschema (1+ depth)))

              ;; Otherwise, fail
              (t
               (format t "~%❌ Unexpected value format in context-specific tag ~A: ~A"
                       (second schema) inner)
               nil)))))

    ;; Fallback: no match
    (t
     (format t "~%❌ No matching clause for element: ~A" element)
     nil)))
