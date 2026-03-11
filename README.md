# cl-rsa-verify

RSA signature verification library for Common Lisp with zero external dependencies.
Verification only - no signing capabilities.

## Installation

```lisp
(asdf:load-system :cl-rsa-verify)
```

## API

- `(rsa-verify public-key message signature)` - Verify RSA signature
- `(pkcs1-v15-verify public-key message signature hash-algo)` - PKCS#1 v1.5 verification
- `(parse-rsa-public-key der-bytes)` - Parse DER-encoded public key
- `(rsa-public-key-p object)` - Check if object is RSA public key
- `(verify-pkcs1-signature n e message signature)` - Low-level verification

## Example

```lisp
(let ((pubkey (cl-rsa-verify:parse-rsa-public-key der-bytes)))
  (cl-rsa-verify:pkcs1-v15-verify pubkey message signature :sha256))
; => T or NIL
```

## License

BSD-3-Clause - Parkian Company LLC 2024-2026
