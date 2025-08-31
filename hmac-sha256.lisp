(defpackage :hmac-sha256
  (:use :cl :shared-utils :sha-utils :sha256)
  (:export :hmac-sha256 :hmac-sha256-hex))

(in-package :hmac-sha256)
(ql:quickload :ironclad)

(defun hmac-sha256 (key message)
  (let* ((block-size 64)
         (key (if (> (length key) block-size)
                  (words-to-bytes (sha256 key))
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
    (let ((inner 
	   (sha256
	    (concatenate '(vector (unsigned-byte 8)) ipad message))))
      ;; Outer hash
      (sha256
       (concatenate '(vector (unsigned-byte 8)) opad (words-to-bytes inner))))))

(defun ironclad-hmac-sha256 (key message)
  (let* ((block-size 64)
         (key (if (> (length key) block-size)
                  (ironclad:digest-sequence :sha256 key)
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
    (let ((inner (ironclad:digest-sequence :sha256
					   (concatenate '(vector (unsigned-byte 8)) ipad message))))
      ;; Outer hash
      (ironclad:byte-array-to-hex-string
       (ironclad:digest-sequence :sha256
				 (concatenate '(vector (unsigned-byte 8)) opad inner))))))

;; for truncating to sha128 for example
(defun hmac-sha256-truncated (key msg &optional (length 16))
  (subseq (hmac-sha256 key msg) 0 length))

(defun hmac-sha256-hex (key message)
  (bytes-to-hex (words-to-bytes (hmac-sha256 key message))))

(format t "~a~%" (sha256-hex (map 'vector #'char-code "abc")))

(defun digest-bytes-to-hex (digest)
  (string-downcase
   (with-output-to-string (s)
     (loop for word across digest
           do (loop for shift from 24 downto 0 by 8
                    do (format s "~2,'0X" (ldb (byte 8 shift) word)))))))

(let ((key (make-array 129 :element-type '(unsigned-byte 8) :initial-element #x0b))
      (msg (map 'vector #'char-code "Hi There")))
  (let ((raw-digest (hmac-sha256 key msg))
        (hex-digest
	 ;;(digest-bytes-to-hex (hmac-sha256 key msg))))
         (bytes-to-hex (words-to-bytes (hmac-sha256 key msg)))))
    (declare (ignore raw-digest))
    ;;(format t "Raw digest      : ~A~%" raw-digest)
    (format t "Ironclad digest : ~A~%" (ironclad-hmac-sha256 key msg))
    (format t "HMAC-SHA256     : ~A~%" (string-downcase hex-digest))))
