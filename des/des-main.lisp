(defpackage :des-main
  (:use :cl :des-utils :des-padding :des-base64 :des-context :des-constants :des-core :des-api)
  (:export :main :repl-main :cli-main))

(in-package :des-main)

(defun parse-cli-args (args)
  "Parse CLI arguments into a plist and positional list."
  (let ((plist '())
        (positional '()))
    (loop for i from 0 below (length args)
          for arg = (nth i args)
          do (cond
	       ((string= arg "--help")    (push :help plist))
               ((string= arg "--decrypt") (push :decrypt plist))
               ((string= arg "--hex")     (push :hex plist))
	       ((string= arg "--base64")  (push :base64 plist))
               ((string= arg "--mode")    (push :mode plist))
               ((string= arg "--key")     (push :key plist))
               ((string= arg "--iv")      (push :iv plist))
               ((and plist (member (car plist) '(:mode :key :iv)))
                (setf (car plist) arg))
               (t (push arg positional))))
    (values (nreverse plist) (nreverse positional))))

(defun cli-main (&rest args)
  "Encrypt or decrypt a file or hex/base64 string using DES."
  (multiple-value-bind (options positional) (parse-cli-args args)
    (let* ((mode (or (getf options :mode) "CBC"))
           (decrypt? (member :decrypt options))
           (hex? (member :hex options))
           (base64? (member :base64 options))
           (key (if (getf options :key)
                    (hex-string-to-byte-vector (getf options :key))
                    (hex-string-to-byte-vector "133457799BBCDFF1")))
           (iv (if (getf options :iv)
                   (hex-string-to-bit-vector (getf options :iv))
                   (make-array 64 :initial-element 0))))

      ;; Validate key and IV lengths
      (unless (= (length key) 8)
	(error "Invalid key length: must be 8 bytes (16 hex characters)"))
      
      (when (string= mode "CBC")
	(unless (= (length iv) 64)
	  (error "Invalid IV length for CBC mode: must be 64 bits (16 hex characters)")))
      
      (cond
        ((or (< (length positional) 2) (member :help options))
         (format t "Usage: cli-main [--decrypt] [--hex|--base64] [--mode ECB|CBC] [--key HEX] [--iv HEX] <input> <output>~%"))

        ;; Base64 string
        ((and base64? (not (probe-file (first positional))))
         (let ((input (first positional))
               (output (second positional)))
           (if decrypt?
               (let ((plain (decrypt-string-base64 input key iv)))
		 (handler-case
                     (with-open-file (out output :direction :output
					  :if-exists :supersede :if-does-not-exist :create)
                       (write-line plain out) :success)
		   (error (e)
		     (format t "File error: ~A~%" e))))
               (let ((cipher (encrypt-string-base64 input key iv)))
		 (handler-case
                 (with-open-file (out output :direction :output
                                      :if-exists :supersede :if-does-not-exist :create)
                   (write-line cipher out) :sucess
		   (error (e)
			  (format t "File error: ~A~%" e))))))))
        
        ;; Base64 file
        (base64?
         (if decrypt?
             (decrypt-base64-file (first positional) (second positional) key iv)
             (encrypt-base64-file (first positional) (second positional) key iv)))

        ;; Hex string
        (hex?
         (let ((input (first positional))
               (output (second positional)))
           (if decrypt?
               (let ((plain (decrypt-hex input key iv)))
		 (handler-case
                 (with-open-file (out output :direction :output
                                      :if-exists :supersede :if-does-not-exist :create)
                   (write-line (byte-vector-to-string plain) out) :sucess
		   (error (e)
			  (format t "File error: ~A~%" e)))))
               (let ((cipher (encrypt-hex input key iv)))
		 (handler-case
                 (with-open-file (out output :direction :output
                                      :if-exists :supersede :if-does-not-exist :create)
                   (write-line (string-to-hex (byte-vector-to-string cipher)) out) :sucess
		   (error (e)
			  (format t "File error: ~A~%" e))))))))

        ;; ECB file
        ((string= mode "ECB")
         (if decrypt?
             (decrypt-file-ecb (first positional) (second positional) key)
             (encrypt-file-ecb (first positional) (second positional) key)))

        ;; CBC file
        (decrypt?
         (decrypt-file (first positional) (second positional) key iv))
        (t
         (encrypt-file (first positional) (second positional) key iv))))))

;; ECB mode file handlers
(defun encrypt-file-ecb (input-path output-path key)
  (handler-case
      (with-open-file (in input-path :direction :input :element-type '(unsigned-byte 8))
	(with-open-file (out output-path :direction :output :element-type '(unsigned-byte 8)
                             :if-exists :supersede :if-does-not-exist :create)
	  (let* ((bytes (read-sequence (make-array (file-length in) :element-type '(unsigned-byte 8)) in))
		 (cipher (encrypt-bytes bytes key)))
            (write-sequence cipher out)
	    :sucess
	    (error (e)
		   (format t "File error: ~A~%" e)))))))

(defun decrypt-file-ecb (input-path output-path key)
  (handler-case
      (with-open-file (in input-path :direction :input :element-type '(unsigned-byte 8))
	(with-open-file (out output-path :direction :output :element-type '(unsigned-byte 8)
                             :if-exists :supersede :if-does-not-exist :create)
	  (let* ((bytes (read-sequence (make-array (file-length in) :element-type '(unsigned-byte 8)) in))
		 (plain (decrypt-bytes bytes key)))
            (write-sequence plain out)
	    :sucess
	    (error (e)
		   (format t "File error: ~A~%" e)))))))

(defun repl-main ()
  "Run a simple test encryption in the REPL."
  (let ((key (hex-string-to-byte-vector "133457799BBCDFF1"))
        (iv (make-array 64 :initial-element 0)))
    (encrypt-hex-cbc "0123456789ABCDEF" key iv)))

(defun main (&rest args)
  "Dispatch to CLI or REPL based on arguments."
  (if args
      (apply #'cli-main args)
      (repl-main)))
