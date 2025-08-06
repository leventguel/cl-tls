(defpackage :tls-extensions
  (:use :cl)
  (:export :build-extension
           :build-extensions
           :build-sni-extension
           :build-sig-algs-extension
           :build-supported-groups-extension))

(in-package :tls-extensions)

(defun build-extension (ext-type ext-data)
  "Build a single extension: 2-byte type, 2-byte length, ext-data bytes."
  (let ((ext-length (length ext-data)))
    (append (list (ldb (byte 8 8) ext-type)
                  (ldb (byte 8 0) ext-type) ; extension type (2 bytes)
                  (ldb (byte 8 8) ext-length)
                  (ldb (byte 8 0) ext-length)) ; extension length (2 bytes)
            ext-data)))

(defun build-extensions (extensions)
  "Build full extensions block with total length prefix."
  (let* ((ext-bytes (mapcan (lambda (ext)
                              (apply #'build-extension ext))
                            extensions))
         (total-length (length ext-bytes)))
    (append
     (list (ldb (byte 8 8) total-length)
           (ldb (byte 8 0) total-length)) ; total extensions length (2 bytes)
     ext-bytes)))

(defun build-sni-extension (hostnames)
  (let ((server-names-bytes
         (mapcan (lambda (hostname)
                   (let* ((name-bytes (map 'list #'char-code hostname))
                          (name-length (length name-bytes)))
                     ;; Name Type (host_name = 0) + 2-byte length + name-bytes
                     (append (list 0)
                             (list (ldb (byte 8 8) name-length)
                                   (ldb (byte 8 0) name-length))
                             name-bytes)))
                 hostnames)))
    ;; Total length of server_names (2 bytes) + server_names bytes
    (let ((total-length (length server-names-bytes)))
      (append (list (ldb (byte 8 8) total-length)
                    (ldb (byte 8 0) total-length))
              server-names-bytes))))

(defun build-sig-algs-extension ()
  "Build Signature Algorithms extension data.
Each algorithm is represented by a pair of bytes: (hash, signature)."
  ;; List of sig algs: pairs of (hash, signature), each 2 bytes
  ;; For example: (0x04 0x01) = SHA256 + RSA
  (let ((sig-algs '(
                    #x04 #x01  ; SHA256 + RSA
                    #x05 #x01  ; SHA384 + RSA
                    #x06 #x01  ; SHA512 + RSA
                    #x02 #x03  ; SHA1 + ECDSA
                    #x04 #x03  ; SHA256 + ECDSA
                    )))
    ;; Length of the sig-algs vector in bytes
    (let ((length (length sig-algs))) ; safe even if odd
      (append (list (ldb (byte 8 8) length)
                    (ldb (byte 8 0) length))
              sig-algs))))

(defun build-supported-groups-extension ()
  "Build supported groups extension data."
  (let ((groups '(#x0017 #x0018 #x0019))) ;; Example: secp256r1, secp384r1,secp521r1
    (let ((groups-bytes (mapcan (lambda (g)
                                  (list (ldb (byte 8 8) g) (ldb (byte 8 0) g)))
                                groups))
          (length (* 2 (length groups))))
      (append (list (ldb (byte 8 8) length)
                    (ldb (byte 8 0) length))
              groups-bytes))))

(defun main ()
  (format t "~%SNI Extension Bytes:~%")
  (print-hex (build-extension 0 (build-sni-extension '("example.com")))))
