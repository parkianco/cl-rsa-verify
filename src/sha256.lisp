;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: BSD-3-Clause

;;;; sha256.lisp
;;;; SHA-256 implementation for RSA-PKCS1

(in-package #:cl-rsa-verify)

;;; SHA-256 Constants

;; Use defvar to avoid SBCL DEFCONSTANT-UNEQL on array constants
(defvar +sha256-k+
  #(#x428a2f98 #x71374491 #xb5c0fbcf #xe9b5dba5
    #x3956c25b #x59f111f1 #x923f82a4 #xab1c5ed5
    #xd807aa98 #x12835b01 #x243185be #x550c7dc3
    #x72be5d74 #x80deb1fe #x9bdc06a7 #xc19bf174
    #xe49b69c1 #xefbe4786 #x0fc19dc6 #x240ca1cc
    #x2de92c6f #x4a7484aa #x5cb0a9dc #x76f988da
    #x983e5152 #xa831c66d #xb00327c8 #xbf597fc7
    #xc6e00bf3 #xd5a79147 #x06ca6351 #x14292967
    #x27b70a85 #x2e1b2138 #x4d2c6dfc #x53380d13
    #x650a7354 #x766a0abb #x81c2c92e #x92722c85
    #xa2bfe8a1 #xa81a664b #xc24b8b70 #xc76c51a3
    #xd192e819 #xd6990624 #xf40e3585 #x106aa070
    #x19a4c116 #x1e376c08 #x2748774c #x34b0bcb5
    #x391c0cb3 #x4ed8aa4a #x5b9cca4f #x682e6ff3
    #x748f82ee #x78a5636f #x84c87814 #x8cc70208
    #x90befffa #xa4506ceb #xbef9a3f7 #xc67178f2)
  "SHA256 round constants.")

(defvar +sha256-init+
  #(#x6a09e667 #xbb67ae85 #x3c6ef372 #xa54ff53a
    #x510e527f #x9b05688c #x1f83d9ab #x5be0cd19)
  "SHA256 initial hash values.")

;;; Utility functions

(declaim (inline u32+ rotr32 shr))

(defun u32+ (&rest args)
  "32-bit addition with wrap."
  (ldb (byte 32 0) (apply #'+ args)))

(defun rotr32 (x n)
  "32-bit rotate right."
  (logior (ldb (byte 32 0) (ash x (- n)))
          (ldb (byte 32 0) (ash x (- 32 n)))))

(defun shr (x n)
  "Logical shift right."
  (ash x (- n)))

;;; SHA-256 functions

(defun sha256-ch (x y z)
  (logxor (logand x y) (logand (lognot x) z)))

(defun sha256-maj (x y z)
  (logxor (logand x y) (logand x z) (logand y z)))

(defun sha256-sigma0 (x)
  (logxor (rotr32 x 2) (rotr32 x 13) (rotr32 x 22)))

(defun sha256-sigma1 (x)
  (logxor (rotr32 x 6) (rotr32 x 11) (rotr32 x 25)))

(defun sha256-gamma0 (x)
  (logxor (rotr32 x 7) (rotr32 x 18) (shr x 3)))

(defun sha256-gamma1 (x)
  (logxor (rotr32 x 17) (rotr32 x 19) (shr x 10)))

;;; Padding and processing

(defun sha256-pad (message)
  "Pad message according to SHA-256 spec."
  (let* ((msg-len (length message))
         (msg-bits (* msg-len 8))
         ;; Padded length: message + 1 + padding + 8 bytes length
         ;; Must be multiple of 64
         (padded-len (* 64 (ceiling (+ msg-len 9) 64)))
         (result (make-array padded-len :element-type '(unsigned-byte 8)
                                        :initial-element 0)))
    ;; Copy message
    (replace result message)
    ;; Append 1 bit (0x80)
    (setf (aref result msg-len) #x80)
    ;; Append length in bits (big-endian, 64-bit)
    (loop for i from 0 below 8
          do (setf (aref result (- padded-len 1 i))
                   (ldb (byte 8 (* i 8)) msg-bits)))
    result))

(defun sha256-process-block (block h)
  "Process one 64-byte block."
  (let ((w (make-array 64 :element-type '(unsigned-byte 32))))
    ;; Prepare message schedule
    (loop for i from 0 below 16
          for j = (* i 4)
          do (setf (aref w i)
                   (logior (ash (aref block j) 24)
                           (ash (aref block (+ j 1)) 16)
                           (ash (aref block (+ j 2)) 8)
                           (aref block (+ j 3)))))
    (loop for i from 16 below 64
          do (setf (aref w i)
                   (u32+ (sha256-gamma1 (aref w (- i 2)))
                         (aref w (- i 7))
                         (sha256-gamma0 (aref w (- i 15)))
                         (aref w (- i 16)))))
    ;; Initialize working variables
    (let ((a (aref h 0)) (b (aref h 1)) (c (aref h 2)) (d (aref h 3))
          (e (aref h 4)) (f (aref h 5)) (g (aref h 6)) (hh (aref h 7)))
      ;; Main loop
      (loop for i from 0 below 64
            for t1 = (u32+ hh (sha256-sigma1 e) (sha256-ch e f g)
                           (aref +sha256-k+ i) (aref w i))
            for t2 = (u32+ (sha256-sigma0 a) (sha256-maj a b c))
            do (setf hh g
                     g f
                     f e
                     e (u32+ d t1)
                     d c
                     c b
                     b a
                     a (u32+ t1 t2)))
      ;; Update hash values
      (setf (aref h 0) (u32+ (aref h 0) a)
            (aref h 1) (u32+ (aref h 1) b)
            (aref h 2) (u32+ (aref h 2) c)
            (aref h 3) (u32+ (aref h 3) d)
            (aref h 4) (u32+ (aref h 4) e)
            (aref h 5) (u32+ (aref h 5) f)
            (aref h 6) (u32+ (aref h 6) g)
            (aref h 7) (u32+ (aref h 7) hh)))))

(defun sha256 (message)
  "Compute SHA-256 hash of message (byte array).
   Returns 32-byte hash."
  (let ((h (copy-seq +sha256-init+))
        (padded (sha256-pad message)))
    ;; Process each 64-byte block
    (loop for i from 0 below (length padded) by 64
          do (sha256-process-block (subseq padded i (+ i 64)) h))
    ;; Convert to bytes
    (let ((result (make-array 32 :element-type '(unsigned-byte 8))))
      (loop for i from 0 below 8
            for word = (aref h i)
            do (setf (aref result (* i 4)) (ldb (byte 8 24) word)
                     (aref result (+ (* i 4) 1)) (ldb (byte 8 16) word)
                     (aref result (+ (* i 4) 2)) (ldb (byte 8 8) word)
                     (aref result (+ (* i 4) 3)) (ldb (byte 8 0) word)))
      result)))
