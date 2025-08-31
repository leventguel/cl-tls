(defpackage :des-macros
  (:use :cl :des-utils :des-padding :des-base64 :des-constants :des-core :des-context :des-api)
  (:export :define-double-des-file-variant :define-triple-des-file-variant))

(in-package :des-macros)

;; some macros
(defmacro define-double-des-file-variant (name mode base64-p)
  `(defun ,(intern (format nil "DOUBLE-DES-~A-~A-FILE~@[~A~]" mode
			   (if base64-p "DECRYPT" "ENCRYPT")
			   (if base64-p "-BASE64" "")))
       (input-path output-path key1 key2 key3)
     ,(format nil "~A file using Double DES ~A~@[ Base64~] mode."
	      (if base64-p "Decrypt" "Encrypt") mode
	      (if base64-p " Base64" nil))
     (let ((data (des-utils:read-file-as-string input-path)))
       (des-utils:write-string-to-file
        output-path
        (double-des:,(intern
		      (format nil "DOUBLE-DES-~A-~A~@[~A~]" mode
			      (if base64-p "DECRYPT" "ENCRYPT")
			      (if base64-p "-BASE64" "")))
         data key1 key2 key3)))))

;; some macros
(defmacro define-triple-des-file-variant (name mode base64-p)
  `(defun ,(intern (format nil "TRIPLE-DES-~A-~A-FILE~@[~A~]" mode
			   (if base64-p "DECRYPT" "ENCRYPT")
			   (if base64-p "-BASE64" "")))
       (input-path output-path key1 key2 key3)
     ,(format nil "~A file using Triple DES ~A~@[ Base64~] mode."
	      (if base64-p "Decrypt" "Encrypt") mode
	      (if base64-p " Base64" nil))
     (let ((data (des-utils:read-file-as-string input-path)))
       (des-utils:write-string-to-file
        output-path
        (triple-des:,(intern
		      (format nil "TRIPLE-DES-~A-~A~@[~A~]" mode
			      (if base64-p "DECRYPT" "ENCRYPT")
			      (if base64-p "-BASE64" "")))
         data key1 key2 key3)))))

;; use like
;; (define-triple-des-file-variant ctr decrypt t)
;; (define-triple-des-file-variant ctr encrypt t)
;; (define-triple-des-file-variant ecb decrypt nil)
