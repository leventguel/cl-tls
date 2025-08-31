(defpackage :tls-aes256-mac
  (:use :cl :shared-utils :tls-aes-utils :tls-aes256)
  (:export :cbcmac-aes256 :cmac-aes256))

(in-package :tls-aes256-mac)

(defun gf128-dbl (block)
  (let ((res (make-array 16 :element-type '(unsigned-byte 8))))
    (let ((carry 0))
      (loop for i from 15 downto 0
            for b = (aref block i)
            do (setf (aref res i)
                     (logand #xFF (logxor (ash b 1) carry))
                     carry (if (logtest b #x80) 1 0)))
      (when (logtest (aref block 0) #x80)
        (setf (aref res 15) (logxor (aref res 15) #x87))))
    res))

(defun generate-subkeys (key)
  (let* ((L (aes256-ecb-encrypt-block
             (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)
             key))
         (K1 (gf128-dbl L))
         (K2 (gf128-dbl K1)))
    (values K1 K2)))

(defun pad-block (block)
  (let ((pad-len (- 16 (length block))))
    (concatenate '(vector (unsigned-byte 8))
                 block
                 (list #x80)
                 (make-array (- pad-len 1) :element-type '(unsigned-byte 8) :initial-element 0))))

(defun cbcmac-aes256 (message key &optional (block-size 16))
  "Computes CBC-MAC using AES-256. Message must be a multiple of block-size."
  (unless (= (mod (length message) block-size) 0)
    (error "Message length must be a multiple of block size for CBC-MAC."))
  (let* ((expanded-key (expand-key-256 key))
         (iv (make-array block-size :element-type '(unsigned-byte 8) :initial-element 0))
         (previous-block iv))
    (loop for i from 0 below (length message) by block-size
          for block = (subseq message i (+ i block-size))
          do (setf previous-block
                   (aes256-cbc-encrypt-block block previous-block expanded-key)))
    previous-block)) ;; Final block is the MAC

(defun cmac-aes256 (msg key tlen)
  "Computes CMAC using AES-256 and returns tlen-byte MAC."
  (multiple-value-bind (K1 K2) (generate-subkeys key)
    (let* ((blocks (split-into-blocks msg 16))
           (expanded-key (expand-key-256 key))
           (prev (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)))
      (cond
        ((null blocks)
         (setf prev
               (aes256-ecb-encrypt-block
                (xor-blocks (pad-block #()) K2)
                expanded-key)))
        (t
         (let* ((n (length blocks))
                (last-block (if (= (mod (length msg) 16) 0)
                                (xor-blocks (nth (- n 1) blocks) K1)
                                (xor-blocks (pad-block (nth (- n 1) blocks)) K2))))
           (loop for i from 0 below (- n 1)
                 do (setf prev
                          (aes256-ecb-encrypt-block
                           (xor-blocks prev (nth i blocks))
                           expanded-key)))
           (setf prev
                 (aes256-ecb-encrypt-block
                  (xor-blocks prev last-block)
                  expanded-key)))))
      (subseq prev 0 tlen))))

(defun test-cbcmac-aes256 ()
  (let* ((key (hex-string-to-byte-vector "603DEB1015CA71BE2B73AEF0857D7781
                                          1F352C073B6108D72D9810A30914DFF4"))
         (message (make-array 32 :element-type '(unsigned-byte 8)
                              :initial-contents (loop for i below 32 collect i)))
         (mac (cbcmac-aes256 message key)))
    (format t "~%CBC-MAC256: ~{~2,'0X~^ ~}~%" (coerce mac 'list))))

(defun test-cmac-aes256 ()
  (let* ((key (hex-string-to-byte-vector "603DEB1015CA71BE2B73AEF0857D7781
                                          1F352C073B6108D72D9810A30914DFF4"))
         (msg #()) ; empty message
         (expected (hex-string-to-byte-vector "028962F61B7BF89EFC6B551F4667D983"))
         (mac (cmac-aes256 msg key 16)))
    (format t "~%CMAC256 Test Result: ~A~%" (equalp mac expected))
    (format t "Expected: ~{~2,'0X~^ ~}~%" (coerce expected 'list))
    (format t "Computed: ~{~2,'0X~^ ~}~%" (coerce mac 'list))))
