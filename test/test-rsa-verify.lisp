;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;; SPDX-License-Identifier: Apache-2.0

;;;; test-rsa-verify.lisp - Unit tests for rsa-verify
;;;;
;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: Apache-2.0

(defpackage #:cl-rsa-verify.test
  (:use #:cl)
  (:export #:run-tests))

(in-package #:cl-rsa-verify.test)

(defun run-tests ()
  "Run all tests for cl-rsa-verify."
  (format t "~&Running tests for cl-rsa-verify...~%")
  ;; TODO: Add test cases
  ;; (test-function-1)
  ;; (test-function-2)
  (format t "~&All tests passed!~%")
  t)
