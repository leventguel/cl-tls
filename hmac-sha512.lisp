(defpackage :hmac-sha512
  (:use :cl :shared-utils :sha-utils :sha512)
  (:export :hmac-sha512 :hmac-sha512-hex))

(in-package :hmac-sha512)
(ql:quickload :ironclad)

(defun hmac-sha512 (key message)
  (let* ((block-size 128)
         (key (if (> (length key) block-size)
                  (words64-to-bytes (sha512 (coerce key '(vector (unsigned-byte 8)))))
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
    (let ((inner (sha512
		  (concatenate '(vector (unsigned-byte 8)) ipad message))))
      ;; Outer hash
      (sha512
       (concatenate '(vector (unsigned-byte 8)) opad (words64-to-bytes inner))))))

(defun ironclad-hmac-sha512 (key message)
  (let* ((block-size 128)
         (key (if (> (length key) block-size)
                  (ironclad:digest-sequence :sha512 key)
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
    (let ((inner (ironclad:digest-sequence :sha512
					   (concatenate '(vector (unsigned-byte 8)) ipad message))))
      ;; Outer hash
      (ironclad:byte-array-to-hex-string
       (ironclad:digest-sequence :sha512
				 (concatenate '(vector (unsigned-byte 8)) opad inner))))))

(defun hmac-sha512-hex (key message)
  (bytes-to-hex (words64-to-bytes (hmac-sha512 key message))))

(format t "~a~%" (sha512-hex (map 'vector #'char-code "abc")))

(defun digest-bytes-to-hex (digest)
  (string-downcase
   (with-output-to-string (s)
     (loop for word across digest
           do (loop for shift from 56 downto 0 by 8
                    do (format s "~2,'0X" (ldb (byte 8 shift) word)))))))

(let ((key (make-array 129 :element-type '(unsigned-byte 8) :initial-element #x0b))
      (msg (map 'vector #'char-code "Hi There")))
  (let ((raw-digest (hmac-sha512 key msg))
	(hex-digest
         (bytes-to-hex (words64-to-bytes (hmac-sha512 key msg)))))
    (declare (ignore raw-digest))
    ;;(format t "Raw digest      : ~A~%" raw-digest)
    (format t "Ironclad digest : ~A~%" (ironclad-hmac-sha512 key msg))
    (format t "HMAC-SHA512     : ~A~%" (string-downcase hex-digest))))
