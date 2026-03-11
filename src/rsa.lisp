;;;; rsa.lisp
;;;; RSA signature verification (no signing)

(in-package #:cl-rsa-verify)

;;; RSA Public Key structure

(defstruct (rsa-public-key (:constructor %make-rsa-public-key))
  "RSA public key."
  (n 0 :type integer)    ; Modulus
  (e 0 :type integer)    ; Public exponent
  (bits 0 :type integer)) ; Key size in bits

;;; Modular exponentiation (square-and-multiply)

(defun mod-expt (base exponent modulus)
  "Compute base^exponent mod modulus using square-and-multiply."
  (declare (type integer base exponent modulus))
  (when (zerop modulus)
    (error "Modulus cannot be zero"))
  (when (minusp exponent)
    (error "Negative exponents not supported"))
  (let ((result 1)
        (base (mod base modulus)))
    (loop while (plusp exponent)
          do (when (oddp exponent)
               (setf result (mod (* result base) modulus)))
             (setf exponent (ash exponent -1))
             (setf base (mod (* base base) modulus)))
    result))

;;; PKCS#1 v1.5 constants

;; Use defvar to avoid SBCL DEFCONSTANT-UNEQL on array constants
(defvar +sha256-digest-info+
  #(#x30 #x31 #x30 #x0d #x06 #x09 #x60 #x86 #x48 #x01 #x65 #x03 #x04 #x02 #x01
    #x05 #x00 #x04 #x20)
  "DER-encoded DigestInfo prefix for SHA-256.")

(defvar +sha1-digest-info+
  #(#x30 #x21 #x30 #x09 #x06 #x05 #x2b #x0e #x03 #x02 #x1a #x05 #x00 #x04 #x14)
  "DER-encoded DigestInfo prefix for SHA-1.")

;;; DER parsing for public keys

(defun parse-der-length (bytes pos)
  "Parse DER length field. Returns (values length new-pos)."
  (let ((first-byte (aref bytes pos)))
    (if (< first-byte 128)
        (values first-byte (1+ pos))
        (let* ((num-bytes (logand first-byte #x7f))
               (length 0))
          (loop for i from 1 to num-bytes
                do (setf length (logior (ash length 8)
                                        (aref bytes (+ pos i)))))
          (values length (+ pos 1 num-bytes))))))

(defun parse-der-integer (bytes pos)
  "Parse DER INTEGER. Returns (values integer new-pos)."
  (unless (= (aref bytes pos) #x02)
    (error "Expected INTEGER tag (0x02)"))
  (multiple-value-bind (len new-pos) (parse-der-length bytes (1+ pos))
    (let ((value 0))
      (loop for i from 0 below len
            do (setf value (logior (ash value 8) (aref bytes (+ new-pos i)))))
      (values value (+ new-pos len)))))

(defun parse-rsa-public-key (der-bytes)
  "Parse DER-encoded RSA public key.
   Supports both PKCS#1 and SubjectPublicKeyInfo formats."
  (let ((pos 0)
        n e)
    ;; Check for SEQUENCE tag
    (unless (= (aref der-bytes pos) #x30)
      (error "Expected SEQUENCE tag"))
    (multiple-value-bind (seq-len new-pos) (parse-der-length der-bytes (1+ pos))
      (declare (ignore seq-len))
      (setf pos new-pos))
    ;; Check if this is SubjectPublicKeyInfo (has AlgorithmIdentifier)
    (when (= (aref der-bytes pos) #x30)
      ;; Skip AlgorithmIdentifier
      (incf pos)
      (multiple-value-bind (alg-len new-pos) (parse-der-length der-bytes pos)
        (setf pos (+ new-pos alg-len)))
      ;; BIT STRING wrapper
      (unless (= (aref der-bytes pos) #x03)
        (error "Expected BIT STRING tag"))
      (incf pos)
      (multiple-value-bind (bs-len new-pos) (parse-der-length der-bytes pos)
        (declare (ignore bs-len))
        (setf pos new-pos))
      ;; Skip unused bits indicator
      (incf pos)
      ;; Inner SEQUENCE
      (unless (= (aref der-bytes pos) #x30)
        (error "Expected inner SEQUENCE"))
      (incf pos)
      (multiple-value-bind (inner-len new-pos) (parse-der-length der-bytes pos)
        (declare (ignore inner-len))
        (setf pos new-pos)))
    ;; Parse n and e
    (multiple-value-setq (n pos) (parse-der-integer der-bytes pos))
    (multiple-value-setq (e pos) (parse-der-integer der-bytes pos))
    (%make-rsa-public-key :n n :e e :bits (integer-length n))))

;;; PKCS#1 v1.5 signature verification

(defun pkcs1-v15-pad-verify (em hash digest-info k)
  "Verify PKCS#1 v1.5 signature padding.
   EM = 0x00 || 0x01 || PS || 0x00 || T
   where PS is padding (0xFF bytes) and T is DigestInfo || hash."
  (let ((t-len (+ (length digest-info) (length hash)))
        (pos 0))
    ;; Check minimum length
    (unless (>= k (+ 11 t-len))
      (return-from pkcs1-v15-pad-verify nil))
    ;; Check 0x00 0x01 prefix
    (unless (and (= (aref em 0) 0)
                 (= (aref em 1) 1))
      (return-from pkcs1-v15-pad-verify nil))
    (setf pos 2)
    ;; Check PS (padding bytes 0xFF)
    (loop while (and (< pos k) (= (aref em pos) #xff))
          do (incf pos))
    ;; Must have at least 8 bytes of padding
    (unless (>= (- pos 2) 8)
      (return-from pkcs1-v15-pad-verify nil))
    ;; Check 0x00 separator
    (unless (= (aref em pos) 0)
      (return-from pkcs1-v15-pad-verify nil))
    (incf pos)
    ;; Check DigestInfo
    (loop for i from 0 below (length digest-info)
          unless (= (aref em (+ pos i)) (aref digest-info i))
            do (return-from pkcs1-v15-pad-verify nil))
    (incf pos (length digest-info))
    ;; Check hash
    (loop for i from 0 below (length hash)
          unless (= (aref em (+ pos i)) (aref hash i))
            do (return-from pkcs1-v15-pad-verify nil))
    t))

(defun integer-to-bytes (n len)
  "Convert integer to big-endian byte array of specified length."
  (let ((result (make-array len :element-type '(unsigned-byte 8)
                                :initial-element 0)))
    (loop for i from (1- len) downto 0
          for j from 0
          do (setf (aref result i) (ldb (byte 8 (* j 8)) n)))
    result))

(defun bytes-to-integer (bytes)
  "Convert big-endian byte array to integer."
  (let ((result 0))
    (loop for byte across bytes
          do (setf result (logior (ash result 8) byte)))
    result))

(defun verify-pkcs1-signature (n e message signature)
  "Low-level PKCS#1 v1.5 verification with SHA-256.
   N and E are public key components.
   MESSAGE is the original message (byte array).
   SIGNATURE is the signature (byte array)."
  (let* ((k (ceiling (integer-length n) 8))  ; Key length in bytes
         (s (bytes-to-integer signature))
         ;; RSA verification: m = s^e mod n
         (m (mod-expt s e n))
         (em (integer-to-bytes m k))
         ;; Hash the message
         (hash (sha256 message)))
    (pkcs1-v15-pad-verify em hash +sha256-digest-info+ k)))

(defun pkcs1-v15-verify (public-key message signature hash-algo)
  "Verify PKCS#1 v1.5 signature.
   PUBLIC-KEY is an rsa-public-key structure.
   MESSAGE is the message (byte array or string).
   SIGNATURE is the signature (byte array).
   HASH-ALGO is :sha256 or :sha1."
  (unless (rsa-public-key-p public-key)
    (error "Invalid public key"))
  (let* ((msg-bytes (etypecase message
                      (string (map '(vector (unsigned-byte 8)) #'char-code message))
                      ((array (unsigned-byte 8) (*)) message)))
         (n (rsa-public-key-n public-key))
         (e (rsa-public-key-e public-key))
         (k (ceiling (integer-length n) 8))
         (s (bytes-to-integer signature))
         (m (mod-expt s e n))
         (em (integer-to-bytes m k))
         (hash (ecase hash-algo
                 (:sha256 (sha256 msg-bytes))
                 (:sha1 (error "SHA-1 not implemented - use SHA-256"))))
         (digest-info (ecase hash-algo
                        (:sha256 +sha256-digest-info+)
                        (:sha1 +sha1-digest-info+))))
    (pkcs1-v15-pad-verify em hash digest-info k)))

(defun rsa-verify (public-key message signature)
  "Verify RSA signature using SHA-256.
   Convenience wrapper for pkcs1-v15-verify."
  (pkcs1-v15-verify public-key message signature :sha256))
