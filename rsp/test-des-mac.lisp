(defpackage :des-mac-test
  (:use :cl :parse-utils :shared-utils :des-utils ::des-double-mac :des-triple-mac :des-mac-parser)
  (:export :test-ddes-cmac-rsp :test-ddes-cmac-rsp-verify
	   :test-tdes-cmac-rsp :test-tdes-cmac-rsp-verify))

(in-package :des-mac-test)

;; CMAC mode
;; TDES2 is DDES (Key1 = Key3)
(defun test-ddes-cmac-rsp (filename &optional verbose-p)
  (let ((cases (parse-ddes-cmac-rsp filename))
        (pass 0)
        (fail 0))
    (dolist (case cases)
      (let* ((key1 (gethash "Key1" case))
             (key2 (gethash "Key2" case))
             (key3 (gethash "Key3" case))
             (msg (if (= 0 (gethash "Mlen" case)) #() (gethash "Msg" case)))
             (expected-mac (gethash "Mac" case))
             (tlen (gethash "Tlen" case))
	     (computed-mac (ddes-cmac msg key1 key2 key3 tlen verbose-p))) ;; Your CMAC function
        (if (equalp computed-mac expected-mac)
	    (progn
	      (incf pass)
	      (when verbose-p
		(progn
		  (format t "~%Msg: ~A~%" (byte-vector-to-hex-string msg))
		  (format t "Expected MAC: ~A~%" (string-downcase (byte-vector-to-hex-string expected-mac)))
		  (format t "Computed MAC: ~A~%" (string-downcase (byte-vector-to-hex-string computed-mac)))
		  (format t "~%✅ CMAC DES Test ~D passed" (gethash "Count" case)))))
	    (progn
	      (incf fail)
	      (when verbose-p
		(progn
		  (format t "~%Key1: ~A~%Key2: ~A~%Key3: ~A~%"
			  (string-downcase (byte-vector-to-hex-string key1))
			  (string-downcase (byte-vector-to-hex-string key2))
			  (string-downcase (byte-vector-to-hex-string key3)))
		  (format t "~%Msg: ~A~%" (byte-vector-to-hex-string msg))
		  (format t "Expected MAC: ~A~%" (string-downcase (byte-vector-to-hex-string expected-mac)))
		  (format t "Computed MAC: ~A~%" (string-downcase (byte-vector-to-hex-string computed-mac)))
		  (format t "~%❌ CMAC DES Test ~D failed" (gethash "Count" case))))))))
    (format t "~%✅ CMAC TDES2 RSP Summary: ~D passed, ~D failed~%" pass fail)))

;; CMAC mode 
;; TDES2 is DDES (Key1 = Key3)
(defun test-ddes-cmac-rsp-verify (filename &optional verbose-p (show-msg-len 120) show-pass-fail)
  (let ((cases (parse-ddes-cmac-rsp-verify filename))
        (pass 0)
        (fail 0)
	(real-passes 0)
	(real-fails 0))
    (dolist (case cases)
      (let* ((key1 (gethash "Key1" case))
             (key2 (gethash "Key2" case))
             (key3 (gethash "Key3" case))
             (msg (if (= 0 (gethash "Mlen" case)) #() (gethash "Msg" case)))
             (expected-mac (gethash "Mac" case))
             (tlen (gethash "Tlen" case))
             (expected-result (gethash "Result" case))
             (computed-mac (ddes-cmac msg key1 key2 key3 tlen verbose-p show-msg-len))
             (match (equalp computed-mac expected-mac))
             (should-pass (string= expected-result "P"))
	     (should-fail (starts-with "F" expected-result)))
	(if show-pass-fail
	  (let ((pass 0)
		(fail 0))
	    (progn
            (if (and match (or (eq match should-pass) (eq nil should-fail)))
		(progn
		  (incf pass)
		  (incf real-passes)
		  (when verbose-p
		    (progn
		      (format t "~%Msg:    ~A ~%(real Mlen ~A)~%"
			      (when (plusp (length msg))
				(subseq (byte-vector-to-hex-string msg) 0 (min show-msg-len (length msg))))
			       (gethash "Mlen" case))
		      (format t "Expected MAC: ~A~%" (string-downcase (byte-vector-to-hex-string expected-mac)))
		      (format t "Computed MAC: ~A~%" (string-downcase (byte-vector-to-hex-string computed-mac)))
		      (format t "Should fail: ~A~%" should-fail)
		      (format t "~%✅ CMAC Verify Test ~D passed" (gethash "Count" case)))))
		(progn
		  (incf fail)
		  (incf real-fails)
		  (when verbose-p
		    (progn
		      (format t "~%Msg:    ~A ~%(real Mlen ~A)~%"
			      (when (plusp (length msg))
				(subseq (byte-vector-to-hex-string msg) 0 (min show-msg-len (length msg))))
			      (gethash "Mlen" case))
		      (format t "Expected MAC: ~A~%" (string-downcase (byte-vector-to-hex-string expected-mac)))
		      (format t "Computed MAC: ~A~%" (string-downcase (byte-vector-to-hex-string computed-mac)))
		      (format t "Should fail: ~A~%" should-fail)
		      (format t "~%❌ CMAC Verify Test ~D failed (expected ~A, got ~A)"
			      (gethash "Count" case)
			      expected-result
			      (if match "P" "F"))))))))
	    ;;(format t "~%✅ CMAC Verify Summary: ~D passed, ~D failed~%" pass fail)))
	(if (or (eq match should-pass) (eq nil should-fail))
	    (progn
	      (incf pass)
	      (when verbose-p
		(progn
		  (format t "~%Msg:    ~A ~%(real Mlen: ~A)~%"
			  (when (plusp (length msg))
			    (subseq (byte-vector-to-hex-string msg) 0 (min show-msg-len (length msg))))
			  (gethash "Mlen" case))
		  (format t "Expected MAC: ~A~%" (string-downcase (byte-vector-to-hex-string expected-mac)))
		  (format t "Computed MAC: ~A~%" (string-downcase (byte-vector-to-hex-string computed-mac)))
		  (format t "Should fail: ~A~%" should-fail)
		  (format t "~%✅ CMAC Verify Test ~D passed" (gethash "Count" case)))))
	    (progn
	      (incf fail)
	      (when verbose-p
		(progn
		  (format t "~%Msg:    ~A ~%(real Mlen: ~A)~%"
			  (when (plusp (length msg))
			    (subseq (byte-vector-to-hex-string msg) 0 (min show-msg-len (length msg))))
			  (gethash "Mlen" case))
		  (format t "Expected MAC: ~A~%" (string-downcase (byte-vector-to-hex-string expected-mac)))
		  (format t "Computed MAC: ~A~%" (string-downcase (byte-vector-to-hex-string computed-mac)))
		  (format t "Should fail: ~A~%" should-fail)
		  (format t "~%❌ CMAC Verify Test ~D failed (expected ~A, got ~A)"
			  (gethash "Count" case)
			  expected-result
			  (if match "P" "F")))))))))
    (when (not show-pass-fail)
      (format t "~%✅ CMAC TDES2 Verify Summary: ~D passed, ~D failed~%" pass fail))
    (when show-pass-fail
      (progn
	(terpri)
	(format t "~%   CMAC TDES2 Verify Expected: ~A passes, ~A fails" 72 288)
	(format t "~%✅ CMAC TDES2 Verify Summary : ~D passes, ~D fails~%" real-passes real-fails)))))

;; CMAC mode
;; TDES3 is TDES (Key1 != Key2 != Key3)
(defun test-tdes-cmac-rsp (filename &optional verbose-p)
  (let ((cases (parse-tdes-cmac-rsp filename))
        (pass 0)
        (fail 0))
    (dolist (case cases)
      (let* ((key1 (gethash "Key1" case))
             (key2 (gethash "Key2" case))
             (key3 (gethash "Key3" case))
             (msg (if (= 0 (gethash "Mlen" case)) #() (gethash "Msg" case)))
             (expected-mac (gethash "Mac" case))
             (tlen (gethash "Tlen" case))
	     (computed-mac (tdes-cmac msg key1 key2 key3 tlen verbose-p))) ;; Your CMAC function
        (if (equalp computed-mac expected-mac)
	    (progn
	      (incf pass)
	      (when verbose-p
		(progn
		  (format t "~%Msg: ~A~%" (byte-vector-to-hex-string msg))
		  (format t "Expected MAC: ~A~%" (string-downcase (byte-vector-to-hex-string expected-mac)))
		  (format t "Computed MAC: ~A~%" (string-downcase (byte-vector-to-hex-string computed-mac)))
		  (format t "~%✅ CMAC DES Test ~D passed" (gethash "Count" case)))))
	    (progn
	      (incf fail)
	      (when verbose-p
		(progn
		  (format t "~%Key1: ~A~%Key2: ~A~%Key3: ~A~%"
			  (string-downcase (byte-vector-to-hex-string key1))
			  (string-downcase (byte-vector-to-hex-string key2))
			  (string-downcase (byte-vector-to-hex-string key3)))
		  (format t "~%Msg: ~A~%" (byte-vector-to-hex-string msg))
		  (format t "Expected MAC: ~A~%" (string-downcase (byte-vector-to-hex-string expected-mac)))
		  (format t "Computed MAC: ~A~%" (string-downcase (byte-vector-to-hex-string computed-mac)))
		  (format t "~%❌ CMAC DES Test ~D failed" (gethash "Count" case))))))))
    (format t "~%✅ CMAC TDES3 DES RSP Summary: ~D passed, ~D failed~%" pass fail)))

;; CMAC mode
;; TDES3 is TDES (Key1 != Key2 != Key3)
(defun test-tdes-cmac-rsp-verify (filename &optional verbose-p (show-msg-len 120) show-pass-fail)
  (let ((cases (parse-tdes-cmac-rsp-verify filename))
        (pass 0)
        (fail 0)
	(real-passes 0)
	(real-fails 0))
    (dolist (case cases)
      (let* ((key1 (gethash "Key1" case))
             (key2 (gethash "Key2" case))
             (key3 (gethash "Key3" case))
             (msg (if (= 0 (gethash "Mlen" case)) #() (gethash "Msg" case)))
             (expected-mac (gethash "Mac" case))
             (tlen (gethash "Tlen" case))
             (expected-result (gethash "Result" case))
             (computed-mac (tdes-cmac msg key1 key2 key3 tlen verbose-p show-msg-len))
             (match (equalp computed-mac expected-mac))
             (should-pass (string= expected-result "P"))
	     (should-fail (starts-with "F" expected-result)))
	(if show-pass-fail
	    (let ((pass 0)
		  (fail 0))
	      (progn
		(if (and match (or (eq match should-pass) (eq nil should-fail)))
		    (progn
		      (incf pass)
		      (incf real-passes)
		      (when verbose-p
			(progn
			  (format t "~%Msg:    ~A ~%(real Mlen: ~A)~%"
				  (when (plusp (length msg))
				    (subseq (byte-vector-to-hex-string msg) 0 (min show-msg-len (length msg))))
				  (gethash "Mlen" case))
			  (format t "Expected MAC: ~A~%" (string-downcase (byte-vector-to-hex-string expected-mac)))
			  (format t "Computed MAC: ~A~%" (string-downcase (byte-vector-to-hex-string computed-mac)))
			  (format t "Should fail: ~A~%" should-fail)
			  (format t "~%✅ CMAC Verify Test ~D passed" (gethash "Count" case)))))
		    (progn
		      (incf fail)
		      (incf real-fails)
		      (when verbose-p
			(progn
			  (format t "~%Msg:    ~A ~%(real Mlen: ~A)~%"
				  (when (plusp (length msg))
				    (subseq (byte-vector-to-hex-string msg) 0 (min show-msg-len (length msg))))
				  (gethash "Mlen" case))
			  (format t "Expected MAC: ~A~%" (string-downcase (byte-vector-to-hex-string expected-mac)))
			  (format t "Computed MAC: ~A~%" (string-downcase (byte-vector-to-hex-string computed-mac)))
			  (format t "Should fail: ~A~%" should-fail)
			  (format t "~%❌ CMAC Verify Test ~D failed (expected ~A, got ~A)"
				  (gethash "Count" case)
			  expected-result
			  (if match "P" "F"))))))))
	    (if (or (eq match should-pass) (eq nil should-fail))
		(progn
		  (incf pass)
		  (when verbose-p
		    (progn
		      (format t "~%Msg:    ~A ~%(real Mlen: ~A)~%"
			      (when (plusp (length msg))
				(subseq (byte-vector-to-hex-string msg) 0 (min show-msg-len (length msg))))
			      (gethash "Mlen" case))
		      (format t "Expected MAC: ~A~%" (string-downcase (byte-vector-to-hex-string expected-mac)))
		      (format t "Computed MAC: ~A~%" (string-downcase (byte-vector-to-hex-string computed-mac)))
		      (format t "Should fail: ~A~%" should-fail)
		      (format t "~%✅ CMAC Verify Test ~D passed" (gethash "Count" case)))))
		(progn
		  (incf fail)
		  (when verbose-p
		    (progn
		      (format t "~%Msg:    ~A ~%(real Mlen: ~A)~%"
			      (when (plusp (length msg))
				(subseq (byte-vector-to-hex-string msg) 0 (min show-msg-len (length msg))))
			      (gethash "Mlen" case))
		      (format t "Expected MAC: ~A~%" (string-downcase (byte-vector-to-hex-string expected-mac)))
		      (format t "Computed MAC: ~A~%" (string-downcase (byte-vector-to-hex-string computed-mac)))
		      (format t "Should fail: ~A~%" should-fail)
		      (format t "~%❌ CMAC Verify Test ~D failed (expected ~A, got ~A)"
			      (gethash "Count" case)
			      expected-result
			      (if match "P" "F")))))))))
    (when (not show-pass-fail)
      (format t "~%✅ CMAC TDES3 Verify Summary: ~D passed, ~D failed~%" pass fail))
    (when show-pass-fail
      (progn
	(terpri)
	(format t "~&   CMAC TDES3 Verify Expected: ~A passes, ~A fails" 48 192)
	(format t "~%✅ CMAC TDES3 Verify Summary : ~D passes, ~D fails~%" real-passes real-fails)))))
