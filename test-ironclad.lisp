(ql:quickload :ironclad)

(defparameter *key* (make-array 20 :element-type '(unsigned-byte 8) :initial-element #x0b))
(defparameter *msg* (map 'vector #'char-code "Hi There"))

(let ((ctx (ironclad:make-hmac :sha1 *key*)))
  (ironclad:update-digest ctx *msg*)
  (ironclad:byte-array-to-hex-string (ironclad:produce-digest ctx)))
