(in-package :aes-test)

(defun verify-sbox-matrix ()
  "Validate the 16×16 AES S-box matrix against FIPS values."
  (let ((fips-sbox
         #(99 124 119 123 242 107 111 197 48 1 103 43 254 215 171 118
           202 130 201 125 250 89 71 240 173 212 162 175 156 164 114 192
           183 253 147 38 54 63 247 204 52 165 229 241 113 216 49 21
           4 199 35 195 24 150 5 154 7 18 128 226 235 39 178 117
           9 131 44 26 27 110 90 160 82 59 214 179 41 227 47 132
           83 209 0 237 32 252 177 91 106 203 190 57 74 76 88 207
           208 239 170 251 67 77 51 133 69 249 2 127 80 60 159 168
           81 163 64 143 146 157 56 245 188 182 218 33 16 255 243 210
           205 12 19 236 95 151 68 23 196 167 126 61 100 93 25 115
           96 129 79 220 34 42 144 136 70 238 184 20 222 94 11 219
           224 50 58 10 73 6 36 92 194 211 172 98 145 149 228 121
           231 200 55 109 141 213 78 169 108 86 244 234 101 122 174 8
           186 120 37 46 28 166 180 198 232 221 116 31 75 189 139 138
           112 62 181 102 72 3 246 14 97 53 87 185 134 193 29 158
           225 248 152 17 105 217 142 148 155 30 135 233 206 85 40 223
           140 161 137 13 191 230 66 104 65 153 45 15 176 84 187 22)))
    (loop for byte from 0 below 256
          for expected = (aref fips-sbox byte)
          for actual = (aref *aes-sbox-matrix*
                             (ash byte -4)
                             (logand byte #x0F))
          do (format t "Byte ~3D (0x~2,'0X): Expected=~3D  Actual=~3D  ~A~%"
                     byte byte expected actual
                     (if (= actual expected) "✓" "❌")))))

(format t "First Verifying AES SBOX:~%")
(verify-sbox-matrix)

(format t "First Verifying AES SBOX:~%")
(verify-sbox-matrix)

(defparameter *test-block*
  #(0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15))

(defparameter *test-key*
  #(1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1))

(defparameter *mix-test*
  #(#xD4 #xBF #x5D #x30 #xE0 #xB4 #x52 #xAE
    #xB8 #x41 #x11 #xF1 #x1E #x27 #x98 #xE5))

(defparameter *expected-shiftrows*
  #(0 1 2 3 5 6 7 4 10 11 8 9 15 12 13 14))

(defparameter *expected-add-round-key*
  #(1 0 3 2 5 4 7 6 9 8 11 10 13 12 15 14))

(defparameter *expected-mix-test*
  #(#x04 #x66 #x81 #xE5 #xE0 #xCB #x19 #x9A
    #x48 #xF8 #xD3 #x7A #x28 #x06 #x26 #x4C))

(defun assert-equal (a b name)
  (if (equalp a b)
      (format t "✔ ~A passed.~%" name)
      (format t "❌ ~A failed.~%Expected: ~{~2,'0X ~}~%Got:      ~{~2,'0X ~}~%"
              name (coerce b 'list) (coerce a 'list))))

(defun run-tests ()
  (format t "~%===== Running AES Unit Tests =====~%")

  ;; Rotate
  (assert-equal (rotate '(1 2 3 4) 1) '(2 3 4 1) "Rotate by 1")
  (assert-equal (rotate '(1 2 3 4) 2) '(3 4 1 2) "Rotate by 2")

  ;; Layout conversions
  (let* ((original #(0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15))
         (converted (from-column-major (to-column-major original))))
    (assert-equal converted original "Row↔Column Conversion"))

  ;; SubBytes (no expected comparison due to dynamic S-box)
  (let ((subbed (sub-bytes-matrix *test-block*)))
    (assert-equal (length subbed) 16 "SubBytes output length"))

  ;; ShiftRows
  (let ((shifted (shift-rows *test-block*)))
    (assert-equal shifted *expected-shiftrows* "ShiftRows"))

  ;; MixColumns
  (let ((mixed (mix-columns *mix-test*)))
    (assert-equal mixed *expected-mix-test* "MixColumns (FIPS block)"))

  ;; AddRoundKey
  (let ((added (add-round-key *test-block* *test-key*)))
    (assert-equal added *expected-add-round-key* "AddRoundKey"))

  ;; xtime and gf-mul
  (assert-equal (xtime #x57) #xAE "xtime(0x57)")
  (assert-equal (gf-mul #x57 #x13) #xFE "gf-mul(0x57, 0x13)")

  ;; rot-word and sub-word (printed only)
  (let* ((w (make-array 4 :element-type '(unsigned-byte 8)
                        :initial-contents '(1 2 3 4)))
         (rot (rot-word w))
	 (srot (safe-rot-word w))
         (sub (sub-word w))
	 (ssub (safe-sub-word w)))
    (format t "RotWord:              ~{~2,'0X ~}~%" (coerce rot 'list))
    (format t "Expected RotWord      ~{~2,'0X ~}~%" (coerce #(02 03 04 01) 'list))
    (format t "SafeRotWord:          ~{~2,'0X ~}~%" (coerce srot 'list))
    (format t "Expected SafeRotWord  ~{~2,'0X ~}~%" (coerce #(02 03 04 01) 'list))
    (format t "SubWord:              ~{~2,'0X ~}~%" (coerce sub 'list))
    (format t "Expected SubWord:     ~{~2,'0X ~}~%" (coerce #(#x7C #x77 #x7B #xF2) 'list))
    (format t "SafeSubWord:          ~{~2,'0X ~}~%" (coerce ssub 'list))
    (format t "Expected SafeSubWord: ~{~2,'0X ~}~%" (coerce #(#x7C #x77 #x7B #xF2) 'list)))
  )

(defun key-expansion-test ()
  (let* ((key-str "2b7e151628aed2a6abf7158809cf4f3c")
	 (key     (hex-string-to-byte-vector key-str))
	 (schedule (expand-key-128 key)))
    (assert-equal (length schedule) 176 "Expanded key length")
    (format t "~%🧪 Key Expansion Sample Output (first 16 bytes):~%~{~2,'0X ~}~%"
            (coerce (subseq schedule 0 16) 'list))))

(defun key-extraction-test ()
  (let ((schedule (expand-key-128 (hex-string-to-byte-vector "2b7e151628aed2a6abf7158809cf4f3c"))))
    (dotimes (i 3)
      (let ((rk (round-key schedule i)))
	(format t "🔑 Round Key ~D: ~{~2,'0X ~}~%" i (coerce rk 'list))))))

(defun encryption-test ()
  (let* ((key-str "2b7e151628aed2a6abf7158809cf4f3c")
	 (pt-str  "6bc1bee22e409f96e93d7e117393172a")
	 (ct-str  "3ad77bb40d7a3660a89ecaf32466ef97")
	 (key     (hex-string-to-byte-vector key-str))
	 (pt      (hex-string-to-byte-vector pt-str))
	 (expected (hex-string-to-byte-vector ct-str))
	 (output   (aes-128-encrypt-block pt key)))
    (assert-equal (length output) 16 "Ciphertext length")
    (format t "🔐 Ciphertext: ~{~2,'0X ~}~%" (coerce output 'list))
    (if (equalp output expected)
	(format t "✔ AES Encryption matches NIST vector.~%")
	(format t "❌ AES Encryption does NOT match.~%"))))
  
(defun run-extended-tests ()
;; ─── Key Expansion ───
(let* ((key-str "2b7e151628aed2a6abf7158809cf4f3c")
       (key     (hex-string-to-byte-vector key-str))
       (schedule (expand-key-128 key)))
  (assert-equal (length schedule) 176 "Expanded key length")
  (format t "~%🧪 Key Expansion Sample Output (first 16 bytes):~%~{~2,'0X ~}~%"
          (coerce (subseq schedule 0 16) 'list)))

;; ─── Round Key Extraction ───
(let ((schedule (expand-key-128 (hex-string-to-byte-vector "2b7e151628aed2a6abf7158809cf4f3c"))))
  (dotimes (i 3)
    (let ((rk (round-key schedule i)))
      (format t "🔑 Round Key ~D: ~{~2,'0X ~}~%" i (coerce rk 'list)))))

;; ─── AES Encryption ───
(let* ((key-str "2b7e151628aed2a6abf7158809cf4f3c")
       (pt-str  "6bc1bee22e409f96e93d7e117393172a")
       (ct-str  "3ad77bb40d7a3660a89ecaf32466ef97")
       (key     (hex-string-to-byte-vector key-str))
       (pt      (hex-string-to-byte-vector pt-str))
       (expected (hex-string-to-byte-vector ct-str))
       (output   (aes-128-encrypt-block pt key)))
  (assert-equal (length output) 16 "Ciphertext length")
  (format t "🔐 Ciphertext: ~{~2,'0X ~}~%" (coerce output 'list))
  (if (equalp output expected)
      (format t "✔ AES Encryption matches NIST vector.~%")
      (format t "❌ AES Encryption does NOT match.~%")))

(format t "===== Tests Completed =====~%"))
