package hoa

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/big"
)

// Group defines a prime-order subgroup. Provision audited production parameters.
type Group struct{ P, Q, G *big.Int }
type Key struct{ Public, Secret *big.Int }

func CheckGroup(v Group) error {
	if v.P == nil || v.Q == nil || v.G == nil || !v.P.ProbablyPrime(64) || !v.Q.ProbablyPrime(64) {
		return errors.New("invalid subgroup primes")
	}
	one := big.NewInt(1)
	if new(big.Int).Mod(new(big.Int).Sub(v.P, one), v.Q).Sign() != 0 || v.G.Cmp(one) <= 0 || v.G.Cmp(v.P) >= 0 || new(big.Int).Exp(v.G, v.Q, v.P).Cmp(one) != 0 {
		return errors.New("invalid generator")
	}
	return nil
}
func DeriveCAKey(v Group, master *big.Int, caID string) (Key, error) {
	if err := CheckGroup(v); err != nil {
		return Key{}, err
	}
	if caID == "" || master == nil || master.Sign() <= 0 || master.Cmp(v.Q) >= 0 {
		return Key{}, errors.New("invalid master or CA")
	}
	// Additively derived CA scalar: x_c = x_root + H(domain,cid) mod q.
	delta := scalar(v.Q, "HM-CertChain/delegation/v1", []byte(caID))
	sk := new(big.Int).Mod(new(big.Int).Add(master, delta), v.Q)
	if sk.Sign() == 0 {
		return Key{}, errors.New("zero CA scalar")
	}
	return Key{Public: new(big.Int).Exp(v.G, sk, v.P), Secret: sk}, nil
}
func VerifyDelegation(v Group, rootPK, caPK *big.Int, caID string) bool {
	if caID == "" || rootPK == nil || caPK == nil || CheckGroup(v) != nil {
		return false
	}
	delta := scalar(v.Q, "HM-CertChain/delegation/v1", []byte(caID))
	t := new(big.Int).Exp(v.G, delta, v.P)
	t.Mul(t, rootPK).Mod(t, v.P)
	return t.Cmp(caPK) == 0
}
func scalar(q *big.Int, domain string, data []byte) *big.Int {
	h := sha256.New()
	h.Write([]byte(domain))
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(len(data)))
	h.Write(b[:])
	h.Write(data)
	return new(big.Int).Mod(new(big.Int).SetBytes(h.Sum(nil)), q)
}
func exponent(v Group, m, t []byte) *big.Int {
	a := scalar(v.Q, "HM-CertChain/HOA-CH/message/v1", m)
	b := scalar(v.Q, "HM-CertChain/HOA-CH/path/v1", t)
	return a.Add(a, b).Mod(a, v.Q)
}
func Verify(v Group, pk *big.Int, m, path []byte, h, r *big.Int) bool {
	if CheckGroup(v) != nil || pk == nil || h == nil || r == nil || r.Sign() < 0 || r.Cmp(v.Q) >= 0 || pk.Sign() <= 0 || pk.Cmp(v.P) >= 0 || h.Sign() <= 0 || h.Cmp(v.P) >= 0 || new(big.Int).Exp(pk, v.Q, v.P).Cmp(big.NewInt(1)) != 0 {
		return false
	}
	lhs := new(big.Int).Exp(v.G, exponent(v, m, path), v.P)
	rhs := new(big.Int).Exp(pk, r, v.P)
	lhs.Mul(lhs, rhs).Mod(lhs, v.P)
	return lhs.Cmp(h) == 0
}
func VerifyAdapt(v Group, pk *big.Int, oldMessage, oldPath, newMessage, newPath []byte, hash, oldR, newR *big.Int) bool {
	return Verify(v, pk, oldMessage, oldPath, hash, oldR) && Verify(v, pk, newMessage, newPath, hash, newR)
}

// SessionCommitment creates a deterministic digest of a migration transcript.
func SessionCommitment(session string, transcript []byte) [32]byte {
	mac := hmac.New(sha256.New, []byte("HM-CertChain/session/v1"))
	var l [8]byte
	binary.BigEndian.PutUint64(l[:], uint64(len(session)))
	mac.Write(l[:])
	mac.Write([]byte(session))
	mac.Write(transcript)
	var out [32]byte
	copy(out[:], mac.Sum(nil))
	return out
}
