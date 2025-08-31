(defsystem des
  :name "des"
  :author "Levent"
  :version "1.0"
  :description "DES encryption suite for CL-Occ"
  :components
  ((:file "des-utils")
   (:file "des-padding")
   (:file "des-base64")
   (:file "des-core")
   (:file "des-context")
   (:file "des-api")
   (:file "des-cli")
   (:file "des-main")
   (:file "des-test")
   (:file "des-benchmark")))
