(defpackage :tls-aes-utils
  (:use :cl)
  (:export :get-bit :set-bit :bits-equal-p :bit-string-to-byte-vector :hex-string-to-byte-vector
	   :byte-vector-to-hex-string :safe-hex-string-to-byte-vector :print-state-grid))

(in-package :tls-aes-utils)

;; ─────────────────────────────
;; Bit Utilities
;; ─────────────────────────────
(defun get-bit (vector bit-index)
  "Gets bit at absolute bit-index from vector."
  (let* ((byte-index (floor bit-index 8))
         (bit-pos (- 7 (mod bit-index 8)))
         (byte (aref vector byte-index)))
    (ldb (byte 1 bit-pos) byte)))

(defun set-bit (vector bit-index value)
  "Sets bit at absolute bit-index in vector to value (0 or 1)."
  (let* ((byte-index (floor bit-index 8))
         (bit-pos (- 7 (mod bit-index 8)))
         (byte (aref vector byte-index)))
    (setf (aref vector byte-index)
          (dpb value (byte 1 bit-pos) byte))))

(defun bits-equal-p (v1 v2 bit-count)
  (loop for i from 0 below bit-count
        always (= (get-bit v1 i) (get-bit v2 i))))

(defun bit-string-to-byte-vector (bitstr)
  "Converts a string of bits (e.g. '1110') to a packed byte vector."
  (let* ((clean (string-trim '(#\Space #\Tab #\Return #\Newline) bitstr))
         (len (length clean))
         (byte-len (ceiling len 8))
         (vec (make-array byte-len :element-type '(unsigned-byte 8))))
    (dotimes (i len)
      (let* ((bit (if (char= (char clean i) #\1) 1 0))
             (byte-idx (floor i 8))
             (bit-pos (- 7 (mod i 8))))
        (setf (aref vec byte-idx)
              (dpb bit (byte 1 bit-pos) (aref vec byte-idx)))))
    vec))

;; ─────────────────────────────
;; Layout Conversion Utilities
;; ─────────────────────────────
(defun hex-string-to-byte-vector (hex)
  "Converts a hex string to a vector of unsigned bytes. Ignores whitespace."
  (let* ((clean (remove-if (lambda (ch) (find ch " \t\n\r")) hex))
         (n (length clean))
         (length-bytes (floor n 2))
         (bytes (make-array length-bytes :element-type '(unsigned-byte 8))))
    (unless (zerop (mod (length clean) 2))
      (error "Hex string must contain an even number of characters"))
    (loop for i from 0 below length-bytes do
      (setf (aref bytes i)
            (parse-integer clean :start (* i 2) :end (+ (* i 2) 2) :radix 16)))
    bytes))

(defun byte-vector-to-hex-string (vec)
  (format nil "~{~2,'0X~}" (coerce vec 'list)))

(defun safe-hex-string-to-byte-vector (s)
  (let ((clean (string-trim '(#\Space #\Tab #\Newline #\Return) s)))
    (if (or (string= clean "")
            (oddp (length clean)))
        (error "Malformed hex string: ~A" clean)
        (hex-string-to-byte-vector clean))))

(defun print-state-grid (state title)
  (format t "~%~A~%" title)
  (dotimes (r 4)
    (loop for c from 0 to 3
          do (format t "~2,'0X " (aref state (+ (* r 4) c))))
    (terpri)))
