(load "load-all.lisp")

(defpackage :tls-state-machine
  (:use :cl :shared-utils :tls-client-hello :tls-server-hello :tls-extensions :tls-records)
  (:export :run-handshake :main))

(in-package :tls-state-machine)

(defparameter premaster
  (make-array 48 :element-type '(unsigned-byte 8) :initial-element #x33))

(defparameter *session-keys* nil)

(defun build-server-hello-record ()
  (let ((cipher-suite '(0 47))  ; TLS_RSA_WITH_AES_128_CBC_SHA
        (extensions `((0 ,(build-sni-extension '("example.com")))
                      (10 ,(build-supported-groups-extension))
                      (13 ,(build-sig-algs-extension))
                      (43 (3 3)))))
    (wrap-in-tls-record (generate-server-hello cipher-suite extensions))))

(defun build-server-cert-record ()
  (wrap-in-tls-record
   (build-certificate-handshake
    (read-cert-from-file "server.der"))))

(defun build-server-hello-done-record ()
  (wrap-in-tls-record (vector #x0E 0 0 0)))

(defun build-client-hello-record ()
  (wrap-in-tls-record (build-client-hello)))

(defun build-client-key-exchange-record ()
  (wrap-in-tls-record (mock-client-key-exchange)))

(defun generate-master-secret (premaster client-random server-random &key
                               (digest #'sha256))
  "Computes TLS master secret using PRF: HMAC(premaster, seed)."
  ;; Seed = "master secret" + client_random + server_random
  (let* ((label (map 'vector #'char-code "master secret"))
         (seed (concatenate '(vector (unsigned-byte 8)) label client-random server-random)))
    ;; Expand using HMAC with premaster as key
    (subseq
     (hmac premaster seed digest
           (case digest ((sha384 sha512) 128) (t 64))
           48) ; output length
     0 48)))

(defun build-change-cipher-spec-record ()
  (wrap-in-tls-record (vector #x14 0 0 1 1))) ; CCS message

(defun log-ssl-key (client-random master-secret)
  "Logs CLIENT_RANDOM entry for Wireshark SSLKEYLOGFILE."
  (with-open-file (out "sslkeylog.log"
                       :direction :output
                       :if-exists :append
                       :if-does-not-exist :create)
    (format out "CLIENT_RANDOM ~A ~A~%"
            (bytes-to-hex client-random)
            (bytes-to-hex master-secret))))

(defun pad-pkcs7 (data block-size)
  "Applies PKCS#7 padding for block-size alignment."
  (let* ((pad-len (- block-size (mod (length data) block-size)))
         (pad-byte (coerce (make-list pad-len :initial-element pad-len)
                           '(vector (unsigned-byte 8)))))
    (concatenate '(vector (unsigned-byte 8)) data pad-byte)))

(defun strip-pkcs7-padding (data)
  "Removes PKCS#7 padding from a byte vector."
  (let* ((pad-len (aref data (- (length data) 1))))
    (subseq data 0 (- (length data) pad-len))))

(defun encrypt-record (plain-text key iv)
  "Encrypts plaintext with AES-128-CBC using key and IV."
  (let* ((padded (pad-pkcs7 plain-text 16)))
    (tls-aes:aes-128-cbc-encrypt padded key iv))) ; requires aes-cbc-encrypt defined in your crypto lib

(defun decrypt-record (encrypted-record key iv)
  ;; decrypt → then:
  (strip-pkcs7-padding decrypted-bytes))

(defun build-application-data-record (plaintext key iv)
  "Wraps encrypted application data in TLS record."
  (let ((ciphertext (encrypt-record plaintext key iv)))
    (concatenate '(vector (unsigned-byte 8))
                 (list #x17 3 3
                       (ldb (byte 8 8) (length ciphertext))
                       (ldb (byte 8 0) (length ciphertext)))
                 ciphertext)))

(defparameter *tls-states*
  '(:client-hello
    :server-hello
    :certificate
    :server-hello-done
    :client-key-exchange
    :change-cipher-spec
    :finished
    :server-finished))

(defun next-state (current)
  (ecase current
    (:client-hello :server-hello)
    (:server-hello :certificate)
    (:certificate :server-hello-done)
    (:server-hello-done :client-key-exchange)
    (:client-key-exchange :change-cipher-spec)
    (:change-cipher-spec :finished)
    (:finished :server-finished)
    (:server-finished nil)))

(defun run-handshake ()
  (let ((transcript (make-array 0 :element-type '(unsigned-byte 8)
                                :adjustable t :fill-pointer 0))
        (state :client-hello)
        ;; Replace with real master secret as needed
        master-secret) ; <- new, unbound initially
    (loop while state do
         (let ((message
                (case state
                  (:client-hello (build-client-hello-record))
                  (:server-hello (build-server-hello-record))
                  (:certificate   (build-server-cert-record))
                  (:server-hello-done (build-server-hello-done-record))
                  (:client-key-exchange
                   (let* ((client-key-exchange-record (build-client-key-exchange-record)))
                     (vector-push-extend client-key-exchange-record transcript)
                     
                     ;; Extract randoms from previously recorded Hello messages
                     (let ((client-random (extract-random-from-hello (aref transcript 0))) ; index may vary
                           (server-random (extract-random-from-hello (aref transcript 1))))
                       (setf master-secret
                             (generate-master-secret premaster client-random server-random))

                       ;; 🔑 PLACE THIS BLOCK RIGHT HERE — after master-secret is computed:
                       (let ((key-block
                               (derive-key-block master-secret server-random client-random 104)))
                         (multiple-value-bind (client-mac-key server-mac-key
                                               client-encrypt-key server-encrypt-key
                                               client-iv server-iv)
                             (values
                              (subseq key-block 0 20)
                              (subseq key-block 20 40)
                              (subseq key-block 40 56)
                              (subseq key-block 56 72)
                              (subseq key-block 72 88)
                              (subseq key-block 88 104))
                           (format t "~%🔑 Client MAC key: ~A~%" (bytes-to-hex client-mac-key))
                           (format t "🔑 Server MAC key: ~A~%" (bytes-to-hex server-mac-key))
                           (format t "🔐 Client Encryption key: ~A~%" (bytes-to-hex client-encrypt-key))
                           (format t "🔐 Server Encryption key: ~A~%" (bytes-to-hex server-encrypt-key))
                           (format t "🧊 Client IV: ~A~%" (bytes-to-hex client-iv))
                           (format t "🧊 Server IV: ~A~%" (bytes-to-hex server-iv))
                           (setf *session-keys*
                                 (list :client-mac client-mac-key
                                       :server-mac server-mac-key
                                       :client-encrypt client-encrypt-key
                                       :server-encrypt server-encrypt-key
                                       :client-iv client-iv
                                       :server-iv server-iv))))
                       (log-ssl-key client-random master-secret))
                     
                     client-key-exchange-record)) ; return this to continue flow
                  (:change-cipher-spec (build-change-cipher-spec-record))
                  (:finished
                   (let* ((handshake-bytes
                           (reduce #'concatenate
                                   (map 'list #'identity transcript)))
                          (verify-data
                           (generate-verify-data handshake-bytes master-secret)))
                     (wrap-in-tls-record (build-finished-record verify-data))))
                  (:server-finished
                   (let* ((received-msg (vector #x14 0 0 12 0 1 2 3 4 5 6 7 8 9 10 11 12)) ; ← update with real content
                          (received-verify-data (subseq received-msg 4 16))
                          (handshake-bytes
                            ;; This should cover everything _up to_ server Finished
                            (reduce #'concatenate
                                    (map 'list #'identity transcript)))
                          (expected-verify-data
                            (generate-verify-data handshake-bytes master-secret)))
                     (if (equalp received-verify-data expected-verify-data)
                         (format t "~%✅ Server Finished verification passed~%")
                         (format t "~%❌ Server Finished verification failed~%"))
                     (wrap-in-tls-record received-msg)))
                  (t
                   (progn
                     (format t "Unhandled state ~A~%" state)
                     #())))))
           (vector-push-extend message transcript)
           (setf state (next-state state))))
    transcript))

(defun main ()
  (let ((transcript (run-handshake)))
    (format t "~%TLS Handshake Transcript Dump~%")
    (print-hex transcript)
    (dump-record transcript)
    (write-hex-lines transcript "tls-hex.txt")))
