;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;; SPDX-License-Identifier: BSD-3-Clause

;;;; cl-rsa-verify.asd
;;;; RSA signature verification - zero external dependencies

(asdf:defsystem #:cl-rsa-verify
  :description "RSA signature verification (no signing)"
  :author "Parkian Company LLC"
  :license "BSD-3-Clause"
  :version "0.1.0"
  :serial t
  :components ((:file "package")
               (:module "src"
                :components ((:file "sha256")
                             (:file "rsa")))))

(asdf:defsystem #:cl-rsa-verify/test
  :description "Tests for cl-rsa-verify"
  :depends-on (#:cl-rsa-verify)
  :serial t
  :components ((:module "test"
                :components ((:file "test-rsa-verify"))))
  :perform (asdf:test-op (o c)
             (let ((result (uiop:symbol-call :cl-rsa-verify.test :run-tests)))
               (unless result
                 (error "Tests failed")))))
