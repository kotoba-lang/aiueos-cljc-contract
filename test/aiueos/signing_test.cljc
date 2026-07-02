(ns aiueos.signing-test
  (:require [aiueos.signing :as signing]
            [clojure.test :refer [deftest is testing]])
  #?(:clj (:import [java.security KeyPairGenerator Signature])))

;; ───────── JVM test helpers: real Ed25519 keypairs + raw signing ─────────
;;
;; `aiueos.signing/verify` only understands raw 32-byte public keys and
;; 64-byte signatures (hex-encoded), so tests need a *real* valid signature to
;; exercise the success path -- a hardcoded fake key/sig pair could never
;; verify. These helpers use the exact same JDK Ed25519 APIs `aiueos.signing`
;; itself uses (see its namespace docstring / `kagi.cacao`), just from the
;; signer's side (KeyPairGenerator + Signature/initSign) instead of the
;; verifier's side.

#?(:clj
   (defn- gen-keypair []
     (.generateKeyPair (KeyPairGenerator/getInstance "Ed25519"))))

#?(:clj
   (defn- raw-public-key-hex
     "A JVM Ed25519 `PublicKey`'s `.getEncoded` is X.509 SubjectPublicKeyInfo:
     a fixed 12-byte DER header + the raw 32-byte key. Strip the header to get
     the raw key `aiueos.signing/verify` expects, hex-encoded."
     [pub]
     (signing/hex-encode (drop 12 (seq (.getEncoded pub))))))

#?(:clj
   (defn- sign-hex
     "Sign `msg` (a String) with `priv` (a JVM Ed25519 `PrivateKey`), return
     the raw 64-byte signature hex-encoded."
     [priv ^String msg]
     (let [s (doto (Signature/getInstance "Ed25519") (.initSign priv))]
       (.update s (.getBytes msg "UTF-8"))
       (signing/hex-encode (.sign s)))))

;; ───────── signed-message shape ─────────

(deftest signed-message-is-id-newline-wasm-sha256
  (is (= "app/notes\ndeadbeef"
         (signing/signed-message {:aiueos/component :app/notes :aiueos/wasm-sha256 "deadbeef"})))
  (is (= "app.notes\ndeadbeef"
         (signing/signed-message {:aiueos/component "app.notes" :aiueos/wasm-sha256 "deadbeef"}))))

(deftest signed-message-is-nil-without-wasm-sha256
  (is (nil? (signing/signed-message {:aiueos/component :app/notes}))))

;; ───────── hex codec ─────────

(deftest hex-decode-encode-round-trip
  (is (= [0 255 16 32 171] (signing/hex-decode "00ff1020ab")))
  (is (= "00ff1020ab" (signing/hex-encode (signing/hex-decode "00ff1020AB")))))

#?(:clj
   (deftest hex-decode-rejects-odd-length
     (is (thrown-with-msg? clojure.lang.ExceptionInfo #"even length"
                            (signing/hex-decode "abc")))))

#?(:clj
   (deftest hex-decode-rejects-an-invalid-digit
     (is (thrown-with-msg? clojure.lang.ExceptionInfo #"invalid hex digit"
                            (signing/hex-decode "zz")))))

;; ───────── verify: pure (host-neutral) deny paths ─────────

(deftest unsigned-manifest-is-unsigned
  (let [m {:aiueos/component :app/notes :aiueos/kind :app}
        result (signing/verify m {:aiueos.policy/signers {}})]
    (is (= {:aiueos.signing/status :unsigned} result))
    (is (signing/unsigned? result))
    (is (not (signing/violation? result)))))

(deftest signature-without-signer-is-a-bad-signature-violation
  (let [m {:aiueos/component :app/notes :aiueos/signature "aabbcc"}
        result (signing/verify m {:aiueos.policy/signers {}})]
    (is (signing/violation? result))
    (is (= :app/notes (:aiueos/component result)))
    (is (= :bad-signature (:aiueos/kind result)))
    (is (re-find #":aiueos/signer" (:aiueos/message result)))))

(deftest signed-manifest-without-wasm-sha256-is-a-bad-signature-violation
  (let [m {:aiueos/component :app/notes :aiueos/signer :signer/alice :aiueos/signature "aabbcc"}
        result (signing/verify m {:aiueos.policy/signers {:signer/alice "00"}})]
    (is (signing/violation? result))
    (is (= :bad-signature (:aiueos/kind result)))
    (is (re-find #"wasm-sha256" (:aiueos/message result)))))

(deftest unregistered-signer-is-a-bad-signature-violation
  (let [m {:aiueos/component :app/notes :aiueos/wasm-sha256 "deadbeef"
           :aiueos/signer :signer/nobody :aiueos/signature "aabbcc"}
        result (signing/verify m {:aiueos.policy/signers {}})]
    (is (signing/violation? result))
    (is (= :bad-signature (:aiueos/kind result)))
    (is (re-find #"not a registered signer" (:aiueos/message result)))))

;; ───────── verify: JVM crypto paths (real Ed25519 keypairs) ─────────

#?(:clj
   (deftest a-valid-signature-verifies
     (let [kp (gen-keypair)
           pub-hex (raw-public-key-hex (.getPublic kp))
           base {:aiueos/component :app/notes :aiueos/wasm-sha256 "deadbeef" :aiueos/signer :signer/alice}
           sig-hex (sign-hex (.getPrivate kp) (signing/signed-message base))
           m (assoc base :aiueos/signature sig-hex)
           policy {:aiueos.policy/signers {:signer/alice pub-hex}}
           result (signing/verify m policy)]
       (is (signing/verified? result))
       (is (= {:aiueos.signing/status :verified :aiueos.signing/signer :signer/alice} result)))))

#?(:clj
   (deftest a-tampered-manifest-fails-verification-not-downgraded-to-unsigned
     (let [kp (gen-keypair)
           pub-hex (raw-public-key-hex (.getPublic kp))
           base {:aiueos/component :app/notes :aiueos/wasm-sha256 "deadbeef" :aiueos/signer :signer/alice}
           sig-hex (sign-hex (.getPrivate kp) (signing/signed-message base))
           ;; the wasm bytes changed after signing -> the signed message no
           ;; longer matches what was actually signed
           tampered (assoc base :aiueos/wasm-sha256 "cafebabe" :aiueos/signature sig-hex)
           policy {:aiueos.policy/signers {:signer/alice pub-hex}}
           result (signing/verify tampered policy)]
       (is (signing/violation? result))
       (is (not (signing/unsigned? result)))
       (is (= :bad-signature (:aiueos/kind result)))
       (is (re-find #"does not verify" (:aiueos/message result))))))

#?(:clj
   (deftest a-signature-from-a-different-keypair-fails-verification
     (let [signer-kp (gen-keypair)
           attacker-kp (gen-keypair)
           pub-hex (raw-public-key-hex (.getPublic signer-kp))
           base {:aiueos/component :app/notes :aiueos/wasm-sha256 "deadbeef" :aiueos/signer :signer/alice}
           wrong-sig-hex (sign-hex (.getPrivate attacker-kp) (signing/signed-message base))
           m (assoc base :aiueos/signature wrong-sig-hex)
           policy {:aiueos.policy/signers {:signer/alice pub-hex}}
           result (signing/verify m policy)]
       (is (signing/violation? result))
       (is (= :bad-signature (:aiueos/kind result))))))

#?(:clj
   (deftest malformed-signature-hex-is-a-violation-not-a-thrown-exception
     (let [kp (gen-keypair)
           pub-hex (raw-public-key-hex (.getPublic kp))
           m {:aiueos/component :app/notes :aiueos/wasm-sha256 "deadbeef"
              :aiueos/signer :signer/alice :aiueos/signature "abc"} ;; odd length
           policy {:aiueos.policy/signers {:signer/alice pub-hex}}
           result (signing/verify m policy)]
       (is (signing/violation? result))
       (is (= :bad-signature (:aiueos/kind result)))
       (is (re-find #"malformed" (:aiueos/message result))))))

#?(:clj
   (deftest malformed-signer-key-hex-is-a-violation
     (let [m {:aiueos/component :app/notes :aiueos/wasm-sha256 "deadbeef"
              :aiueos/signer :signer/alice :aiueos/signature "aabbccdd"}
           policy {:aiueos.policy/signers {:signer/alice "not-hex!!"}}
           result (signing/verify m policy)]
       (is (signing/violation? result))
       (is (= :bad-signature (:aiueos/kind result))))))

#?(:clj
   (deftest wrong-length-key-is-a-violation
     (let [m {:aiueos/component :app/notes :aiueos/wasm-sha256 "deadbeef"
              :aiueos/signer :signer/alice :aiueos/signature "aabbccdd"}
           policy {:aiueos.policy/signers {:signer/alice "aabbcc"}} ;; 3 bytes, not 32
           result (signing/verify m policy)]
       (is (signing/violation? result))
       (is (= :bad-signature (:aiueos/kind result)))
       (is (re-find #"32 bytes" (:aiueos/message result))))))
