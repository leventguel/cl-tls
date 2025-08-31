(defpackage :handshake-helpers
  (:use :cl :shared-utils)
  (:export :generate-verify-data :derive-key-block))

(defun generate-verify-data (handshake-transcript
                             master-secret
                             &key (digest 'sha256) (mac-size 12))
  "Computes TLS Finished message verify_data from transcript and master secret."
  (let ((transcript-hash (words-to-bytes (funcall digest handshake-transcript))))
    (subseq
     (hmac master-secret transcript-hash digest
           ;; Block size: 64 for SHA-256/224/1, 128 for SHA-384/512                                                                     
           (case digest
             ((sha384 sha512) 128)
             (t 64))
           mac-size)
     0 mac-size)))

(defun derive-key-block (master-secret
                         server-random client-random
                         total-length
                         &key (digest 'sha256))
  "Derives key block from TLS master secret using PRF expansion."
  (let* ((label (map 'vector #'char-code "key expansion"))
         (seed (concatenate '(vector (unsigned-byte 8)) label server-random client-random)))
    (subseq
     (hmac master-secret seed digest
           (case digest ((sha384 sha512) 128) (t 64))
           total-length)
     0 total-length)))

(defun wrap-in-tls-record (handshake-message)
  "Wraps a TLS handshake message in a TLS record header."
  (let* ((content-type  #x16)  ; Handshake                                                                                              
         (version-major #x03)
         (version-minor #x03)
         (length (length handshake-message)))
    (concatenate '(vector (unsigned-byte 8))
                 (vector content-type version-major version-minor
                         (ldb (byte 8 8) length)
                         (ldb (byte 8 0) length))
                 handshake-message)))
(defun read-cert-from-file (path)
  "Reads a DER-encoded certificate from a file into a byte vector."
  (with-open-file (stream path :element-type '(unsigned-byte 8))
    (let ((data (make-array (file-length stream)
                            :element-type '(unsigned-byte 8))))
      (read-sequence data stream)
      data)))

;; Use it like (build-handshake-transcript hello cert done) for off the flow testing/constructing message sequences
;; i.e. outside full protocol orchestration
#|
(build-handshake-transcript
 (build-client-hello-record) (build-server-hello-record) (build-server-cert-record)
 (build-server-hello-done-record) (build-client-key-exchange-record) (build-change-cipher-spec-record)
 (build-server-finished-record))
|#
;; which is just the logical flow without the verification part

(defun build-handshake-transcript (&rest records)
  (apply #'concatenate '(vector (unsigned-byte 8)) (copy-seq records)))

;; binary
(defun dump-record (bytes &optional (path "~/clocc/src/ssl/server-handshake.bin"))
  (with-open-file (stream path
                          :direction :output
                          :element-type '(unsigned-byte 8)
                          :if-exists :supersede
                          :if-does-not-exist :create)
    (write-sequence bytes stream)))

(defun extract-random-from-hello (hello-record)
  "Extracts 32-byte random from TLS Hello message.
Assumes TLS record header is 5 bytes and handshake header is 4 bytes.
Random begins at byte offset 10."
  ;; Assuming TLS record header is 5bytes
  ;; Handshake header is 4bytes
  ;; Random starts at byte 6 + 4 = offset 10
  (subseq hello-record 10 42))
