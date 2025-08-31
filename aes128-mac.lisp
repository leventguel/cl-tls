(defpackage :tls-aes128-mac
  (:use :cl :shared-utils :tls-aes-utils :tls-aes128)
  (:export :cbcmac-aes128 :cmac-aes128))

(in-package :tls-aes128-mac)

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
  (let* ((L (aes128-ecb-encrypt-block (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0) key))
         (K1 (gf128-dbl L))
         (K2 (gf128-dbl K1)))
    (values K1 K2)))

(defun pad-block (block)
  (let ((pad-len (- 16 (length block))))
    (concatenate '(vector (unsigned-byte 8))
                 block
                 (list #x80)
                 (make-array (- pad-len 1) :element-type '(unsigned-byte 8) :initial-element 0))))

(defun cbcmac-aes128 (message key &optional (block-size 16))
  "Computes CBC-MAC using AES-128. Message must be a multiple of block-size."
  (unless (= (mod (length message) block-size) 0)
    (error "Message length must be a multiple of block size for CBC-MAC."))
  (let* ((expanded-key (expand-key-128 key))
         (iv (make-array block-size :element-type '(unsigned-byte 8) :initial-element 0))
         (previous-block iv)
         (mac nil))
    (loop for i from 0 below (length message) by block-size
          for block = (subseq message i (+ i block-size))
          do (setf previous-block
                   (aes128-cbc-encrypt-block block previous-block expanded-key)))
    (setf mac previous-block) ;; Final block is the MAC
    mac))

(defun cmac-aes128 (msg key tlen)
  "Computes CMAC using AES-128 and returns tlen-byte MAC."
  (multiple-value-bind (K1 K2) (generate-subkeys key)
    (let* ((blocks (split-into-blocks msg 16))
           (expanded-key (expand-key-128 key))
           (prev (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)))
      (cond
        ;; Empty message: use padded zero block and K2
        ((null blocks)
         (setf prev
               (aes128-ecb-encrypt-block
                (xor-blocks (pad-block #()) K2)
                expanded-key)))
        ;; Non-empty message
        (t
         (let* ((n (length blocks))
                (last-block (if (= (mod (length msg) 16) 0)
                                (xor-blocks (nth (- n 1) blocks) K1)
                                (xor-blocks (pad-block (nth (- n 1) blocks)) K2))))
           (loop for i from 0 below (- n 1)
                 do (setf prev
                          (aes128-ecb-encrypt-block
                           (xor-blocks prev (nth i blocks))
                           expanded-key)))
           (setf prev
                 (aes128-ecb-encrypt-block
                  (xor-blocks prev last-block)
                  expanded-key)))))
	(subseq prev 0 tlen))))

(defun test-cbcmac-aes128 ()
  (let* ((key #(0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15))
         (message (make-array 32 :element-type '(unsigned-byte 8)
                              :initial-contents (loop for i below 32 collect i)))
         (mac (cbcmac-aes128 message key)))
    (format t "~%CBC-MAC: ~{~2,'0X~^ ~}~%" (coerce mac 'list))))

(defun test-cmac-aes128 ()
  (let* ((key (hex-string-to-byte-vector "2B7E151628AED2A6ABF7158809CF4F3C"))
         (msg #()) ; empty message
         (expected (hex-string-to-byte-vector "BB1D6929E95937287FA37D129B756746"))
         (mac (cmac-aes128 msg key 16)))
    (format t "~%CMAC128 Test Result: ~A~%" (equalp mac expected))
    (format t "Expected: ~{~2,'0X~^ ~}~%" (coerce expected 'list))
    (format t "Computed: ~{~2,'0X~^ ~}~%" (coerce mac 'list))))
