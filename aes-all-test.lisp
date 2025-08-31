(load "shared-utils.lisp")
(load "aes-utils.lisp")
(load "sha.lisp")
(load "hmac-sha.lisp")
(load "test-harness-sha.lisp")
(load "test-harness-hmac-sha.lisp")
(load "gf128mul.lisp")
(load "ghash.lisp")
(load "aes128.lisp")
(load "aes192.lisp")
(load "aes256.lisp")
(load "aes128-gcm.lisp")
(load "aes192-gcm.lisp")
(load "aes256-gcm.lisp")
(load "aes128-mac.lisp")
(load "aes192-mac.lisp")
(load "aes256-mac.lisp")
(load "des-all.lisp")
(load "rsp/parse-utils.lisp")
(load "rsp/rsp128-parser.lisp")
(load "rsp/test128.lisp")
(load "rsp/rsp192-parser.lisp")
(load "rsp/test192.lisp")
(load "rsp/rsp256-parser.lisp")
(load "rsp/test256.lisp")
(load "rsp/des-mac-parser.lisp")
(load "rsp/test-des-mac.lisp")

(defpackage :tls-aes-all-test
  (:use :cl :parse-utils :shared-utils :des-utils :tls-aes-utils :sha-utils :sha1 :sha224 :sha256 :sha384 :sha512 :tls-aes128 :tls-aes192 :tls-aes256 :tls-aes-ghash :tls-aes128-gcm :tls-aes192-gcm :tls-aes256-gcm :tls-aes-rsp128-parser :tls-aes-rsp192-parser :tls-aes-rsp256-parser :aes128rsp-test :aes192rsp-test :aes256rsp-test :des-test :des-mac-parser :des-mac-test))

(in-package :tls-aes-all-test)

(defun test-128 ()
  "tests the main MODES (ECB..CTR) for aes128"
  (test-ecb128-rsp            "rsp/mmt/ECBMMT128.rsp")
  (test-ecb128-rsp-decrypt    "rsp/mmt/ECBMMT128.rsp")
  (test-cbc128-rsp            "rsp/mmt/CBCMMT128.rsp")
  (test-cbc128-rsp-decrypt    "rsp/mmt/CBCMMT128.rsp")
  (test-ctr128-rsp            "rsp/ctr/CTRMMT128.rsp")
  (test-ctr128-rsp-decrypt    "rsp/ctr/CTRMMT128.rsp")
  (test-ofb128-rsp            "rsp/mmt/OFBMMT128.rsp")
  (test-ofb128-rsp-decrypt    "rsp/mmt/OFBMMT128.rsp")
  (test-cfb128-rsp            "rsp/mmt/CFB128MMT128.rsp")
  (test-cfb128-rsp-decrypt    "rsp/mmt/CFB128MMT128.rsp")
  (test128-cfb8-rsp           "rsp/mmt/CFB8MMT128.rsp")
  (test128-cfb8-rsp-decrypt   "rsp/mmt/CFB8MMT128.rsp")
  (test128-cfb1-rsp           "rsp/mmt/CFB1MMT128.rsp")
  (test128-cfb1-rsp-decrypt   "rsp/mmt/CFB1MMT128.rsp"))

;; better to split otherwise we don't see the overall result since the tests are long
(defun test-128gcm (&optional verbose-p)
  "tests the GCM MODES for aes128"
  (test128-gcm-rsp            "rsp/gcm/gcmEncryptExtIV128.rsp" verbose-p))

;; better to split otherwise we don't see the overall result since the tests are long
(defun test-128gcm-dec (&optional verbose-p)
  (test128-gcm-rsp-decrypt    "rsp/gcm/gcmDecrypt128.rsp" verbose-p))

(defun test-128cmac ()
  "tests the CMAC MODES for aes128"
  (test-aes128-cmac-rsp           "rsp/cmac/CMACGenAES128.rsp")
  (test-aes128-cmac-rsp-verify    "rsp/cmac/CMACVerAES128.rsp"))

;; use like (tls-aes-all-test::test128)

(defun test-192 ()
  "tests the main MODES (ECB..CTR) for aes192"
(test-ecb192-rsp            "rsp/mmt/ECBMMT192.rsp")
(test-ecb192-rsp-decrypt    "rsp/mmt/ECBMMT192.rsp")
(test-cbc192-rsp            "rsp/mmt/CBCMMT192.rsp")
(test-cbc192-rsp-decrypt    "rsp/mmt/CBCMMT192.rsp")
(test-ctr192-rsp            "rsp/ctr/CTRMMT192.rsp")
(test-ctr192-rsp-decrypt    "rsp/ctr/CTRMMT192.rsp")
(test-ofb192-rsp            "rsp/mmt/OFBMMT192.rsp")
(test-ofb192-rsp-decrypt    "rsp/mmt/OFBMMT192.rsp")
(test-cfb192-rsp            "rsp/mmt/CFB128MMT192.rsp")
(test-cfb192-rsp-decrypt    "rsp/mmt/CFB128MMT192.rsp")
(test192-cfb8-rsp           "rsp/mmt/CFB8MMT192.rsp")
(test192-cfb8-rsp-decrypt   "rsp/mmt/CFB8MMT192.rsp")
(test192-cfb1-rsp           "rsp/mmt/CFB1MMT192.rsp")
(test192-cfb1-rsp-decrypt   "rsp/mmt/CFB1MMT192.rsp"))

(defun test-192gcm (&optional verbose-p)
"tests the GCM MODES for aes192"
(test192-gcm-rsp            "rsp/gcm/gcmEncryptExtIV192.rsp" verbose-p))

;; better to split here otherwise we don't see the overall result since the tests are long
(defun test-192gcm-dec (&optional verbose-p)
(test192-gcm-rsp-decrypt    "rsp/gcm/gcmDecrypt192.rsp" verbose-p))

(defun test-192cmac ()
"tests the CMAC modes for aes192"
(test-aes192-cmac-rsp           "rsp/cmac/CMACGenAES192.rsp")
(test-aes192-cmac-rsp-verify    "rsp/cmac/CMACVerAES192.rsp"))

;; use like (tls-aes-all-test::test192)

(defun test-256 ()
  "tests the main MODES (ECB..CTR) for aes256"
  (test-ecb256-rsp            "rsp/mmt/ECBMMT256.rsp")
  (test-ecb256-rsp-decrypt    "rsp/mmt/ECBMMT256.rsp")
  (test-cbc256-rsp            "rsp/mmt/CBCMMT256.rsp")
  (test-cbc256-rsp-decrypt    "rsp/mmt/CBCMMT256.rsp")
  (test-ctr256-rsp            "rsp/ctr/CTRMMT256.rsp")
  (test-ctr256-rsp-decrypt    "rsp/ctr/CTRMMT256.rsp")
  (test-ofb256-rsp            "rsp/mmt/OFBMMT256.rsp")
  (test-ofb256-rsp-decrypt    "rsp/mmt/OFBMMT256.rsp")
  (test-cfb256-rsp            "rsp/mmt/CFB128MMT256.rsp")
  (test-cfb256-rsp-decrypt    "rsp/mmt/CFB128MMT256.rsp")
  (test256-cfb8-rsp           "rsp/mmt/CFB8MMT256.rsp")
  (test256-cfb8-rsp-decrypt   "rsp/mmt/CFB8MMT256.rsp")
  (test256-cfb1-rsp           "rsp/mmt/CFB1MMT256.rsp")
  (test256-cfb1-rsp-decrypt   "rsp/mmt/CFB1MMT256.rsp"))

;; better to split otherwise we don't see the overall result since the tests are long
(defun test-256gcm (&optional verbose-p)
  "tests the GCM MODES for aes256"
  (test256-gcm-rsp            "rsp/gcm/gcmEncryptExtIV256.rsp" verbose-p))

;; better to split otherwise we don't see the overall result since the tests are long
(defun test-256gcm-dec (&optional verbose-p)
  (test256-gcm-rsp-decrypt    "rsp/gcm/gcmDecrypt256.rsp" verbose-p))

(defun test-256cmac ()
  "tests the CMAC MODES for aes256"
  (test-aes256-cmac-rsp           "rsp/cmac/CMACGenAES256.rsp")
  (test-aes256-cmac-rsp-verify    "rsp/cmac/CMACVerAES256.rsp"))

;; use like (tls-aes-all-test::test256)
;; DDES and TDES tests
(defun test-ddes-cmac (&optional verbose-p)
  "tests the CMAC MODES for aes128"
  (test-ddes-cmac-rsp           "rsp/cmac/CMACGenTDES2.rsp" verbose-p))

(defun test-ddes-cmac-ver (&optional verbose-p (show-msg-len 120) show-pass-fail)
  (test-ddes-cmac-rsp-verify    "rsp/cmac/CMACVerTDES2.rsp" verbose-p show-msg-len show-pass-fail))

(defun test-tdes-cmac (&optional verbose-p)
  "tests the CMAC MODES for aes128"
  (test-tdes-cmac-rsp           "rsp/cmac/CMACGenTDES3.rsp" verbose-p))

(defun test-tdes-cmac-ver (&optional verbose-p (show-msg-len 120) show-pass-fail)
  (test-tdes-cmac-rsp-verify    "rsp/cmac/CMACVerTDES3.rsp" verbose-p show-msg-len show-pass-fail))

(defun test-all ()
  (test-128)
  (test-128gcm)
  (test-128gcm-dec)
  (test-128cmac)
  (test-192)
  (test-192gcm)
  (test-192gcm-dec)
  (test-192cmac)
  (test-256)
  (test-256gcm)
  (test-256gcm-dec)
  (test-256cmac)
  (test-ddes-cmac)
  (test-ddes-cmac-ver)
  (test-tdes-cmac)
  (test-tdes-cmac-ver)
  (run-all-des-tests)
  (sha1::run-all-tests)
  (sha224::run-all-tests)
  (sha256::run-all-tests)
  (sha384::run-all-tests)
  (sha512::run-all-tests)
  (hmac-sha1::run-all-tests)
  (hmac-sha224::run-all-tests)
  (hmac-sha256::run-all-tests)
  (hmac-sha384::run-all-tests)
  (hmac-sha512::run-all-tests))
;; run like tls-aes-all-test::test-all if you want all tests
