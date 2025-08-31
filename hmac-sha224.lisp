(defpackage :hmac-sha224
  (:use :cl :shared-utils :sha-utils :sha224)
  (:export :hmac-sha224 :hmac-sha224-hex))

(in-package :hmac-sha224)
(ql:quickload :ironclad)

(defun hmac-sha224 (key message)
  (let* ((block-size 64)
         (key (if (> (length key) block-size)
                  (words-to-bytes (sha224 key))
                  key))
         (key (concatenate '(vector (unsigned-byte 8))
                           key
                           (make-array (- block-size (length key))
                                       :element-type '(unsigned-byte 8)
                                       :initial-element 0)))
         (ipad (make-array block-size :element-type '(unsigned-byte 8)
                           :initial-element #x36))
         (opad (make-array block-size :element-type '(unsigned-byte 8)
                           :initial-element #x5c)))
    ;; XOR key with ipad and opad
    (loop for i from 0 below block-size do
	  (setf (aref ipad i) (logxor (aref ipad i) (aref key i))
		(aref opad i) (logxor (aref opad i) (aref key i))))
    ;; Inner hash
    (let ((inner (sha224
		  (concatenate '(vector (unsigned-byte 8)) ipad message))))
      ;; Outer hash
      (sha224
       (concatenate '(vector (unsigned-byte 8)) opad (words-to-bytes inner))))))

(defun ironclad-hmac-sha224 (key message)
  (let* ((block-size 64)
         (key (if (> (length key) block-size)
                  (ironclad:digest-sequence :sha224 key)
                  key))
         (key (concatenate '(vector (unsigned-byte 8))
                           key
                           (make-array (- block-size (length key))
                                       :element-type '(unsigned-byte 8)
                                       :initial-element 0)))
         (ipad (make-array block-size :element-type '(unsigned-byte 8)
                           :initial-element #x36))
         (opad (make-array block-size :element-type '(unsigned-byte 8)
                           :initial-element #x5c)))
    (loop for i from 0 below block-size do
	  (setf (aref ipad i) (logxor (aref ipad i) (aref key i))
		(aref opad i) (logxor (aref opad i) (aref key i))))
    ;; Inner hash                                                                  
    (let ((inner (ironclad:digest-sequence :sha224
					   (concatenate '(vector (unsigned-byte 8)) ipad message))))
      ;; Outer hash
      (ironclad:byte-array-to-hex-string
       (ironclad:digest-sequence :sha224
				 (concatenate '(vector (unsigned-byte 8)) opad inner))))))

(defun hmac-sha224-hex (key message)
  (bytes-to-hex (words-to-bytes (hmac-sha224 key message))))

(format t "~a~%" (sha224-hex (map 'vector #'char-code "abc")))

(defun digest-bytes-to-hex (digest)
  (string-downcase
   (with-output-to-string (s)
     (loop for word across digest
           do (loop for shift from 24 downto 0 by 8
                    do (format s "~2,'0X" (ldb (byte 8 shift) word)))))))

(let ((key (make-array 20 :element-type '(unsigned-byte 8) :initial-element #x0b)) ;; 64bit max and then it wraps
      (msg (map 'vector #'char-code "Hi There")))
  (let ((raw-digest (hmac-sha224 key msg))
	(hex-digest
	 (bytes-to-hex (words-to-bytes (hmac-sha224 key msg)))))
    (declare (ignore raw-digest))
    ;;(format t "Raw digest      : ~A~%" raw-digest)
    (format t "Ironclad digest : ~A~%" (ironclad-hmac-sha224 key msg))
    (format t "HMAC-SHA224     : ~A~%" (string-downcase hex-digest))))
