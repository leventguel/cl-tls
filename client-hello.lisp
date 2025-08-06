(load "utils.lisp")
(load "tls-extensions.lisp")

(defpackage :tls-client-hello
  (:use :cl)
  (:export :build-client-hello))

(in-package :tls-client-hello)

(defun build-client-hello ()
  (let* ((protocol-version #x0303)
         (random (generate-random-data 32))
         (session-id-length 0)
         (cipher-suites '(#x002F #xC013))
         (compression-methods '(#x00))
         (extensions (list
                      (build-extension 0 (build-sni-extension '("example.com")))
                      (build-extension 10 (build-supported-groups-extension))
                      (build-extension 13 (build-sig-algs-extension))))
         (extensions-bytes (apply #'append extensions))
         (extensions-length (length extensions-bytes))
         (cipher-suites-bytes (mapcan (lambda (cs)
                                        (list (ldb (byte 8 8) cs)
                                              (ldb (byte 8 0) cs)))
                                      cipher-suites))
         (cipher-suites-length (* 2 (length cipher-suites)))
         (total-length (+ 2 ; version
                          32 ; random
                          1 ; session ID length
                          session-id-length
                          2 cipher-suites-length
                          1 (length compression-methods)
                          2 extensions-length))
         (client-hello (make-array total-length :element-type '(unsigned-byte 8))))
    (let ((offset 0))
      ;; Version
      (setf (aref client-hello offset) (ldb (byte 8 8) protocol-version))
      (setf (aref client-hello (incf offset)) (ldb (byte 8 0) protocol-version))
      (incf offset)

      ;; Random
      (dotimes (i 32)
        (setf (aref client-hello (+ offset i)) (aref random i)))
      (incf offset 32)

      ;; Session ID
      (setf (aref client-hello offset) session-id-length)
      (incf offset)

      ;; Cipher Suites
      (setf (aref client-hello offset) (ldb (byte 8 8) cipher-suites-length))
      (setf (aref client-hello (incf offset)) (ldb (byte 8 0) cipher-suites-length))
      (incf offset)
      (dolist (byte cipher-suites-bytes)
        (setf (aref client-hello offset) byte)
        (incf offset))

      ;; Compression Methods
      (setf (aref client-hello offset) (length compression-methods))
      (incf offset)
      (dolist (cm compression-methods)
        (setf (aref client-hello offset) cm)
        (incf offset))

      ;; Extensions
      (setf (aref client-hello offset) (ldb (byte 8 8) extensions-length))
      (setf (aref client-hello (incf offset)) (ldb (byte 8 0) extensions-length))
      (incf offset)
      (dolist (byte extensions-bytes)
        (setf (aref client-hello offset) byte)
        (incf offset)))

    client-hello))

(defun main ()
  (let* ((hello (build-client-hello))
         (record (wrap-in-tls-record hello)))
    (format t "Generated ClientHello message:~%")
    (print-hex hello)
    (format t "ClientHello Record Layer Hex Dump:~%")
    (print-hex record)))
