;;;; cl-rsa-verify.asd
;;;; RSA signature verification - zero external dependencies

(asdf:defsystem #:cl-rsa-verify
  :description "RSA signature verification (no signing)"
  :author "Parkian Company LLC"
  :license "BSD-3-Clause"
  :version "1.0.0"
  :serial t
  :components ((:file "package")
               (:module "src"
                :components ((:file "sha256")
                             (:file "rsa")))))
