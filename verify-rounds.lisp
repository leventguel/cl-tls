(in-package :aes-test)

(defun load-aes-key (hex-str &key (layout :row-major))
  (let ((bytes (hex-string-to-byte-vector hex-str)))
    (ecase layout
      (:row-major bytes)
      (:column-major bytes))))

(defun get-round-key (expanded round &key (layout :row-major))
  "Returns round key as 16-byte vector in given layout."
  (let ((raw (round-key expanded round)))
    (ecase layout
      (:column-major (to-column-major raw))
      (:row-major raw))))

;;; 🔍 Comparison Macro
(defmacro verify-stage (actual expected label)
  `(progn
     (format t "~%🔎 Verifying ~A~%" ,label)
     (dotimes (i 16)
       (let ((a (aref ,actual i))
             (e (aref ,expected i)))
         (unless (equalp a e)
           (format t "❌ Byte ~D mismatch: expected ~2,'0X, got ~2,'0X~%" i e a))))))

(defun verify-round-key (expanded round expected-hex &key (layout :row-major))
  (let* ((actual (round-key expanded round))
         (expected (hex-string-to-byte-vector expected-hex)))
    (format t "~%🔍 Verifying Round ~D in ~A:" round layout)
    (dotimes (i 16)
      (let ((a (aref actual i))
            (e (aref expected i)))
        (format t " ~2,'0X~A"
                a
                (if (equalp a e) "" (format nil "~% ≠ ~2,'0X" e)))))
    (unless (equalp actual expected)
      (format t " ❌ mismatch"))))

(defun verify-expanded-key-128 (expanded expected-words)
  "Compares expanded flat key against expected 4-byte word vectors."
  (loop for i from 0 below 44
        for actual = (make-array 4 :element-type '(unsigned-byte 8)
                                 :initial-contents (subseq expanded (* i 4) (+ (* i 4) 4)))
        for expected = (aref expected-words i)
        do
          (format t "~%🔍 w[~D]:" i)
          (dotimes (j 4)
            (let ((a (aref actual j))
                  (e (aref expected j)))
              (format t " ~2,'0X~A"
                      a
                      (if (= a e) "" (format nil " ≠ ~2,'0X" e)))))
          (unless (every #'= actual expected)
            (format t " ❌ mismatch"))))

(defparameter *fips-key-schedule*
  (make-array 44 :element-type 'vector
              :initial-contents
              (mapcar #'(lambda (bytes)
                          (make-array 4 :element-type '(unsigned-byte 8)
                                      :initial-contents bytes))
                      '((#x2B #x7E #x15 #x16)
                        (#x28 #xAE #xD2 #xA6)
                        (#xAB #xF7 #x15 #x88)
                        (#x09 #xCF #x4F #x3C)
                        (#xA0 #xFA #xFE #x17)
                        (#x88 #x54 #x2C #xB1)
                        (#x23 #xA3 #x39 #x39)
                        (#x2A #x6C #x76 #x05)
                        (#xF2 #xC2 #x95 #xF2)
                        (#x7A #x96 #xB9 #x43)
                        (#x59 #x35 #x80 #x7A)
                        (#x73 #x59 #xF6 #x7F)
                        (#x3D #x80 #x47 #x7D)
                        (#x47 #x16 #xFE #x3E)
                        (#x1E #x23 #x7E #x44)
                        (#x6D #x7A #x88 #x3B)
                        (#xEF #x44 #xA5 #x41)
                        (#xA8 #x52 #x5B #x7F)
                        (#xB6 #x71 #x25 #x3B)
                        (#xDB #x0B #xAD #x00)
                        (#xD4 #xD1 #xC6 #xF8)
                        (#x7C #x83 #x9D #x87)
                        (#xCA #xF2 #xB8 #xBC)
                        (#x11 #xF9 #x15 #xBC)
                        (#x6D #x88 #xA3 #x7A)
                        (#x11 #x0B #x3E #xFD)
                        (#xDB #xF9 #x86 #x41)
                        (#xCA #x00 #x93 #xFD)
                        (#x4E #x54 #xF7 #x0E)
                        (#x5F #x5F #xC9 #xF3)
                        (#x84 #xA6 #x4F #xB2)
                        (#x4E #xA6 #xDC #x4F)
                        (#xEA #xD2 #x73 #x21)
                        (#xB5 #x8D #xBA #xD2)
                        (#x31 #x2B #xF5 #x60)
                        (#x7F #x8D #x29 #x2F)
                        (#xAC #x77 #x66 #xF3)
                        (#x19 #xFA #xDC #x21)
                        (#x28 #xD1 #x29 #x41)
                        (#x57 #x5C #x00 #x6E)
                        (#xD0 #x14 #xF9 #xA8)
                        (#xC9 #xEE #x25 #x89)
                        (#xE1 #x3F #x0C #xC8)
                        (#xB6 #x63 #x0C #xA6)))))

(defparameter *fips-round-hex-keys*
  '("2b7e151628aed2a6abf7158809cf4f3c"
    "a0fafe1788542cb123a339392a6c7605"
    "f2c295f27a96b9435935807a7359f67f"
    "3d80477d4716fe3e1e237e446d7a883b"
    "ef44a541a8525b7fb671253bdb0bad00"
    "d4d1c6f87c839d87caf2b8bc11f915bc"
    "6d88a37a110b3efddbf98641ca0093fd"
    "4e54f70e5f5fc9f384a64fb24ea6dc4f"
    "ead27321b58dbad2312bf5607f8d292f"
    "ac7766f319fadc2128d12941575c006e"
    "d014f9a8c9ee2589e13f0cc8b6630ca6"))

(defun verify-round-keys-against-fips (expanded fips-round-hex-keys)
  (dotimes (round 10)
    (let* ((rk (round-key expanded round)) ; ensure row-major
           (expected (hex-string-to-byte-vector (nth round fips-round-hex-keys))))
      (format t "~%🔍 Round ~D:" round)
      (dotimes (i 16)
        (let ((a (aref rk i))
              (e (aref expected i)))
          (when (/= a e)
            (format t " ❌ Byte ~D mismatch: expected ~2,'0X, got ~2,'0X~%"
                    i e a)))))))

;;; 🔐 Official AES-128 Test Vectors
(defparameter *key-str* "2b7e151628aed2a6abf7158809cf4f3c")
(defparameter *pt-str*  "6bc1bee22e409f96e93d7e117393172a")
(defparameter *pt64-str*  "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710")
(defparameter *ct-str*  "3ad77bb40d7a3660a89ecaf32466ef97")
(defparameter *ct64-str*  "3ad77bb40d7a3660a89ecaf32466ef97f5d3d58503b9699de785895a96fdbaaf43b1cd7f598ece23881b00e3ed0306887b0c785e27e8ad3f8223207104725dd4")

(defparameter *key* (hex-string-to-byte-vector *key-str*))
(defparameter *pt*  (hex-string-to-byte-vector *pt-str*))
(defparameter *pt64*  (hex-string-to-byte-vector *pt64-str*))
(defparameter *expected-ct* (hex-string-to-byte-vector *ct-str*))
(defparameter *expanded-key* (expand-key-128 *key*))

(defun row-to-column-major (vec)
  (let ((out (make-array 16 :element-type '(unsigned-byte 8))))
    ;; vec is row-major: [r0c0 r0c1 r0c2 r0c3 r1c0 r1c1 ...]
    ;; convert to col-major: [r0c0 r1c0 r2c0 r3c0 r0c1 r1c1 ...]
    (dotimes (row 4)
      (dotimes (col 4)
        (setf (aref out (+ (* col 4) row)) ; column-major index
              (aref vec (+ (* row 4) col))))) ; row-major index
    out))

(defun column-to-row-major (vec)
  (let ((out (make-array 16 :element-type '(unsigned-byte 8))))
    ;; vec is column-major: [r0c0 r1c0 r2c0 r3c0 r0c1 r1c1 ...]
    ;; convert to row-major: [r0c0 r0c1 r0c2 r0c3 r1c0 r1c1 ...]
    (dotimes (row 4)
      (dotimes (col 4)
        (setf (aref out (+ (* row 4) col))
              (aref vec (+ (* col 4) row)))))
    out))

(defun test-round-key ()
  (let ((expanded (expand-key-128 *key*)))
    (dotimes (round 11)
      (let ((rk (round-key expanded round))
	    (expected (hex-string-to-byte-vector (nth round *fips-round-hex-keys*))))
        (format t "~%🧪 Round ~D Key Test:~%" round)
        ;; ✅ Fix: print correct w[i] for each round
	#|
        (dotimes (i 4)
	  (let* ((word-index (+ (* round 4) i))
		 (start (* word-index 4))
		 (end (+ start 4)))
	    (when (> end (length expanded)) ; guard against overflow
	      (let ((w (subseq expanded start end)))
	(format t "w[~D] = ~{~2,'0X~^ ~}~%" word-index (coerce w 'list)))))
	|#
        ;; Redundant printing of w[i] removed to avoid confusion
          (let ((a (aref rk round))
                (e (aref expected round)))
            (if (not (equalp a e))
                (format t " ❌ Byte ~D mismatch: expected ~2,'0X, got ~2,'0X~%" round e a)
                (format t "~%Actual: ~2,'0X~%Expected: ~2,'0X~%" a e)))
	  (print expected)
	  (print rk)
        (format t "~%round-key: ~{~2,'0X ~}~%" (coerce rk 'list))
        (format t "expected : ~{~2,'0X ~}~%" (coerce expected 'list))))))

(verify-expanded-key-128 *expanded-key* *fips-key-schedule*)

(verify-round-keys-against-fips *expanded-key* *fips-round-hex-keys*)

;;; 📥 Expected Intermediate States from Round 0 and Round 1
(defparameter *expected-r0*
  (hex-string-to-byte-vector "40bfabf406ee4d3042ca6b997a5c5816"))
(defparameter *expected-r1-after-sub*
  (hex-string-to-byte-vector "090862bf6f28e3042c747feeda4a6a47"))
(defparameter *expected-r1-after-shift*
  (hex-string-to-byte-vector "09287f476f746abf2c4a6204da08e3ee"))
(defparameter *expected-r1-after-mix*
  (hex-string-to-byte-vector "529f16c2978615cae01aae54ba1a2659"))
(defparameter *expected-r1-final*
  (hex-string-to-byte-vector "f265e8d51fd2397bc3b9976d9076505c"))

;;; 🧱 Run AES Step-by-Step
(defparameter *state* (copy-seq *pt*))

(format t "~%")
(print-state-grid *state* "🧾 Initial AES State:")
(print-state-grid (round-key *expanded-key* 0) "🔑 Round 0 Key:")

;;; Round 0
(setf *state* (add-round-key *state* (round-key *expanded-key* 0)))
(print-state-grid *state* "🌀 After Round 0 AddRoundKey")
(verify-stage *state* *expected-r0* "Round 0 AddRoundKey")

;;; Round 1 (verbose verification)
(format t "~%=== Round 1 ===~%")
(setf *state* (sub-bytes-matrix *state*))
(print-state-grid *state* "🔬 After SubBytes")
(verify-stage *state* *expected-r1-after-sub* "Round 1 After SubBytes")

(setf *state* (shift-rows *state*))
(print-state-grid *state* "🔄 After ShiftRows")
(verify-stage *state* *expected-r1-after-shift* "Round 1 After ShiftRows")

(setf *state* (mix-columns *state*))
(print-state-grid *state* "🔗 After MixColumns")
(verify-stage *state* *expected-r1-after-mix* "Round 1 After MixColumns")

(setf *state* (add-round-key *state* (round-key *expanded-key* 1)))
(print-state-grid *state* "🔐 After AddRoundKey")
(verify-stage *state* *expected-r1-final* "Round 1 Final State")

;;; Rounds 2 to 9
(dotimes (round 8)
  (let ((n (+ round 2)))
    (format t "~%=== Round ~D ===~%" n)
    (setf *state* (sub-bytes-matrix *state*))
    (print-state-grid *state* "🔬 After SubBytes")
    (setf *state* (shift-rows *state*))
    (print-state-grid *state* "🔄 After ShiftRows")
    (setf *state* (mix-columns *state*))
    (print-state-grid *state* "🔗 After MixColumns")
    (setf *state* (add-round-key *state* (round-key *expanded-key* n)))
    (print-state-grid *state* "🔐 After AddRoundKey")))

;;; Final Round (Round 10)
(format t "~%=== Final Round ===~%")
(setf *state* (sub-bytes-matrix *state*))
(print-state-grid *state* "🔬 Final SubBytes")
(setf *state* (shift-rows *state*))
(print-state-grid *state* "🔄 Final ShiftRows")
(setf *state* (add-round-key *state* (round-key *expanded-key* 10)))
(print-state-grid *state* "🔐 Final AddRoundKey")

;;; 🎯 Final Output Comparison
(defparameter *output*  *state*)

(format t "~%✅ Final Output: ~{~2,'0X~^ ~}~%" (coerce *output* 'list))
(format t "🎯 Expected CT:  ~{~2,'0X~^ ~}~%" (coerce *expected-ct* 'list))
(format t "⚖️  Match?       ~A~%" (equalp *output* *expected-ct*))

(dotimes (i 16)
  (let ((actual (aref *output* i))
        (expected (aref *expected-ct* i)))
    (unless (= actual expected)
      (format t "❌ Byte ~D mismatch: expected ~2,'0X, got ~2,'0X~%" i expected actual))))

;;; 🧪 MixColumns Unit Test
(defparameter *test-column* (vector #xDB #x13 #x53 #x45))
(defparameter *expected-mixed* (vector #x8E #x4D #xA1 #xBC))

(format t "~%🔬 Testing MixColumns column~%")
(format t "Input:    ~{~2,'0X~^ ~}~%" (coerce *test-column* 'list))
(format t "Expected: ~{~2,'0X~^ ~}~%" (coerce *expected-mixed* 'list))
(format t "Output:   ~{~2,'0X~^ ~}~%" (coerce (mix-column *test-column*) 'list))

;;; 🧪 ShiftRows Unit Test
(defparameter *shift-input*
  (hex-string-to-byte-vector "6309cdba53d070e6e47bd3a13f854517"))
(defparameter *expected-shift*
  (hex-string-to-byte-vector "6309cdbad070e653d3a1e47b173f8545"))
(defparameter *actual-shift* (shift-rows *shift-input*))

(format t "~%🔬 Testing ShiftRows~%")
(format t "Input:    ~{~2,'0X~^ ~}~%" (coerce *shift-input* 'list))
(format t "Expected: ~{~2,'0X~^ ~}~%" (coerce *expected-shift* 'list))
(format t "Output:   ~{~2,'0X~^ ~}~%" (coerce *actual-shift* 'list))

;;; 🧪 AddRoundKey Unit Test
(defparameter *ark-input*
  (hex-string-to-byte-vector "046681e5e0cb199a48f8d37a2806264c"))
(defparameter *ark-key*
  (hex-string-to-byte-vector "a088232afa54a36cfe2c397617b13905"))
(defparameter *ark-expected*
  (hex-string-to-byte-vector "a4eea2cf1a9fbaf6b6d4ea0c3fb71f49"))
(defparameter *ark-output* (add-round-key *ark-input* *ark-key*))

(format t "~%🔬 Testing AddRoundKey~%")
(format t "Input:    ~{~2,'0X~^ ~}~%" (coerce *ark-input* 'list))
(format t "Key:      ~{~2,'0X~^ ~}~%" (coerce *ark-key* 'list))
(format t "Expected: ~{~2,'0X~^ ~}~%" (coerce *ark-expected* 'list))
(format t "Output:   ~{~2,'0X~^ ~}~%" (coerce *ark-output* 'list))

(dotimes (i 16)
  (let ((actual (aref *ark-output* i))
        (expected (aref *ark-expected* i)))
    (unless (= actual expected)
      (format t "❌ Byte ~D mismatch: expected ~2,'0X, got ~2,'0X~%" i expected actual))))

;;; 🎯 Final AES Output Comparison
(defparameter *output* *state*)

(format t "~%✅ Final Output: ~{~2,'0X~^ ~}~%" (coerce *output* 'list))
(format t "🎯 Expected CT:  ~{~2,'0X~^ ~}~%" (coerce *expected-ct* 'list))
(format t "⚖️  Match?       ~A~%" (equalp *output* *expected-ct*))

(verify-round-key *expanded-key* 0  "2b7e151628aed2a6abf7158809cf4f3c")
(verify-round-key *expanded-key* 1  "a0fafe1788542cb123a339392a6c7605")
(verify-round-key *expanded-key* 2  "f2c295f27a96b9435935807a7359f67f")
(verify-round-key *expanded-key* 3  "3d80477d4716fe3e1e237e446d7a883b")
(verify-round-key *expanded-key* 4  "ef44a541a8525b7fb671253bdb0bad00")
(verify-round-key *expanded-key* 5  "d4d1c6f87c839d87caf2b8bc11f915bc")
(verify-round-key *expanded-key* 6  "6d88a37a110b3efddbf98641ca0093fd")
(verify-round-key *expanded-key* 7  "4e54f70e5f5fc9f384a64fb24ea6dc4f")
(verify-round-key *expanded-key* 8  "ead27321b58dbad2312bf5607f8d292f")
(verify-round-key *expanded-key* 9  "ac7766f319fadc2128d12941575c006e")
(verify-round-key *expanded-key* 10 "d014f9a8c9ee2589e13f0cc8b6630ca6")
