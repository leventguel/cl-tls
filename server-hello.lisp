(load "shared-utils.lisp")
(load "tls-extensions.lisp")

(defpackage :tls-server-hello
  (:use :cl)
  (:export :generate-server-hello :build-certificate-handshake))

(in-package :tls-server-hello)

(defun generate-server-hello (cipher-suite extensions)
  (let* ((protocol-version '(#x03 #x03))
         (server-random (loop for i from 1 to 32 collect (random 256)))
         (session-id '())
         (session-id-length (length session-id))
         (compression-method '(0))
         (ext-bytes (build-extensions extensions))
         (message-body (append
                        protocol-version
                        server-random
                        (list session-id-length)
                        session-id
                        cipher-suite
                        compression-method
                        ext-bytes))
         (message-body-length (length message-body))
         (length-field (list
                        (ldb (byte 8 16) message-body-length)
                        (ldb (byte 8 8) message-body-length)
                        (ldb (byte 8 0) message-body-length)))
         (server-hello (append
                        (list 2)  ; message type
                        length-field
                        message-body)))
    server-hello))

(defun build-certificate-handshake (cert-bytes)
  "Wraps a DER cert as a TLS Certificate handshake message."
  (let* ((cert-len (length cert-bytes))
         (cert-len-bytes (list (ldb (byte 8 16) cert-len)
                               (ldb (byte 8 8) cert-len)
                               (ldb (byte 8 0) cert-len)))
         (cert-list (append cert-len-bytes (coerce cert-bytes 'list)))
         (cert-list-len (length cert-list))
         (cert-list-len-bytes (list (ldb (byte 8 16) cert-list-len)
                                    (ldb (byte 8 8) cert-list-len)
                                    (ldb (byte 8 0) cert-list-len)))
         (handshake-body (append cert-list-len-bytes cert-list))
         (handshake-len (length handshake-body))
         (handshake-header (list #x0b  ; Handshake type: Certificate
                                 (ldb (byte 8 16) handshake-len)
                                 (ldb (byte 8 8) handshake-len)
                                 (ldb (byte 8 0) handshake-len))))
    (coerce (append handshake-header handshake-body) '(vector (unsigned-byte 8)))))


;; Main function to generate and print the ServerHello message
(defun main ()
  (let ((cipher-suite '(0 47))  ; Cipher suite TLS_RSA_WITH_AES_128_CBC_SHA (corrected)
        (extensions `((0 ,(build-sni-extension '("example.com")))
                      (10 ,(build-supported-groups-extension))
                      (13 ,(build-sig-algs-extension))
                      (43  (3 3)))))
    (let* ((server-hello (generate-server-hello cipher-suite extensions))
           (hello-record (wrap-in-tls-record server-hello))
           (cert-bytes (read-cert-from-file "server.der"))
           (cert-msg (build-certificate-handshake cert-bytes))
           (cert-record (wrap-in-tls-record cert-msg)))
      (format t "Cipher Suite: ~A~%" cipher-suite)
      (format t "Message body: ~A~%" (subseq server-hello 4))
      (format t "Message body length: ~A~%" (length (subseq server-hello 4)))
      (format t "Length field: ~A~%" (subseq server-hello 1 4))
      (format t "~%ServerHello Message with extensions: ~A~%" server-hello)
      (format t "~%ServerHello Record Layer Hex Dump~%")
      (print-hex hello-record)
      (format t "~%ServerHello Cert Record Dump~%")
      (print-hex cert-record)
      (let ((transcript (concatenate '(vector (unsigned-byte 8)) hello-record cert-record)))
        (format t "~%Handshake Transcript~%")
        (print-hex transcript)
        (dump-record transcript)
        (write-hex-lines transcript "tls-hex.txt")))))
