package sw

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/big"
)

// HOAParameters is a subgroup G=<g> of Z_p* with prime order q.
// Production deployments MUST provision independently audited >=2048-bit p,
// >=256-bit q, and a generator of order q. Validation of parameter origin
// and strength is a deployment responsibility; toy parameters are unsafe.
type HOAParameters struct{ P, Q, G *big.Int }
type HOAKeyPair struct{ Public, Secret *big.Int }

func NewHOAParameters(p, q, g *big.Int) (*HOAParameters, error) {
	if p == nil || q == nil || g == nil {
		return nil, errors.New("nil group parameter")
	}
	if !p.ProbablyPrime(32) || !q.ProbablyPrime(32) {
		return nil, errors.New("p and q must be prime")
	}
	one := big.NewInt(1)
	if new(big.Int).Mod(new(big.Int).Sub(p, one), q).Sign() != 0 {
		return nil, errors.New("q must divide p-1")
	}
	if g.Cmp(one) <= 0 || g.Cmp(p) >= 0 || new(big.Int).Exp(g, q, p).Cmp(one) != 0 {
		return nil, errors.New("invalid subgroup generator")
	}
	return &HOAParameters{new(big.Int).Set(p), new(big.Int).Set(q), new(big.Int).Set(g)}, nil
}
func hoaScalar(p *HOAParameters) (*big.Int, error) {
	if p == nil || p.Q == nil {
		return nil, errors.New("invalid parameters")
	}
	for {
		x, e := rand.Int(rand.Reader, p.Q)
		if e != nil {
			return nil, e
		}
		if x.Sign() != 0 {
			return x, nil
		}
	}
}

// Setup samples a master key. The group parameters must be provisioned beforehand.
func HOASetup(params *HOAParameters) (*HOAKeyPair, error) {
	x, e := hoaScalar(params)
	if e != nil {
		return nil, e
	}
	return &HOAKeyPair{Public: new(big.Int).Exp(params.G, x, params.P), Secret: x}, nil
}

// AuthSetup generates a CA-bound adaptation key pair. CA authorization and
// delegated key custody MUST be enforced by the surrounding protocol.
func HOAAuthSetup(params *HOAParameters, caID string) (*HOAKeyPair, error) {
	if caID == "" {
		return nil, errors.New("empty CA ID")
	}
	return HOASetup(params)
}
func hoaDigestScalar(q *big.Int, domain string, raw []byte) *big.Int {
	h := sha256.New()
	h.Write([]byte(domain))
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(raw)))
	h.Write(n[:])
	h.Write(raw)
	return new(big.Int).Mod(new(big.Int).SetBytes(h.Sum(nil)), q)
}
func hoaExponent(p *HOAParameters, message, trustPath []byte) *big.Int {
	a := hoaDigestScalar(p.Q, "HM-CertChain/HOA-CH/message/v1", message)
	b := hoaDigestScalar(p.Q, "HM-CertChain/HOA-CH/path/v1", trustPath)
	return a.Add(a, b).Mod(a, p.Q)
}
func validPublic(params *HOAParameters, public *big.Int) bool {
	if params == nil || public == nil || public.Sign() <= 0 || public.Cmp(params.P) >= 0 {
		return false
	}
	return new(big.Int).Exp(public, params.Q, params.P).Cmp(big.NewInt(1)) == 0
}
func validScalar(params *HOAParameters, x *big.Int) bool {
	return x != nil && x.Sign() >= 0 && x.Cmp(params.Q) < 0
}

// HOAHash computes h = g^(Hm(m)+Ht(T)) * pk^r (mod p).
func HOAHash(params *HOAParameters, public *big.Int, message, trustPath []byte) (hash, randomness *big.Int, err error) {
	if !validPublic(params, public) {
		return nil, nil, errors.New("invalid public key")
	}
	r, e := hoaScalar(params)
	if e != nil {
		return nil, nil, e
	}
	z := new(big.Int).Exp(params.G, hoaExponent(params, message, trustPath), params.P)
	t := new(big.Int).Exp(public, r, params.P)
	return z.Mul(z, t).Mod(z, params.P), r, nil
}
func HOAVerify(params *HOAParameters, public *big.Int, message, trustPath []byte, hash, randomness *big.Int) bool {
	if !validPublic(params, public) || !validScalar(params, randomness) || hash == nil || hash.Sign() <= 0 || hash.Cmp(params.P) >= 0 {
		return false
	}
	z := new(big.Int).Exp(params.G, hoaExponent(params, message, trustPath), params.P)
	t := new(big.Int).Exp(public, randomness, params.P)
	return z.Mul(z, t).Mod(z, params.P).Cmp(hash) == 0
}

// HOAAdapt computes r'=r+(Hm(m)+Ht(T)-Hm(m')-Ht(T'))/sk mod q.
// The caller MUST authorize the migration instance and never expose sk.
func HOAAdapt(params *HOAParameters, key *HOAKeyPair, oldMessage, oldPath, newMessage, newPath []byte, hash, oldR *big.Int) (*big.Int, error) {
	if key == nil || key.Secret == nil || key.Public == nil || !validScalar(params, key.Secret) || key.Secret.Sign() == 0 {
		return nil, errors.New("invalid adaptation key")
	}
	if new(big.Int).Exp(params.G, key.Secret, params.P).Cmp(key.Public) != 0 {
		return nil, errors.New("key mismatch")
	}
	if !HOAVerify(params, key.Public, oldMessage, oldPath, hash, oldR) {
		return nil, errors.New("old hash verification failed")
	}
	oldE := hoaExponent(params, oldMessage, oldPath)
	newE := hoaExponent(params, newMessage, newPath)
	delta := oldE.Sub(oldE, newE).Mod(oldE, params.Q)
	inv := new(big.Int).ModInverse(key.Secret, params.Q)
	if inv == nil {
		return nil, errors.New("noninvertible key")
	}
	delta.Mul(delta, inv).Mod(delta, params.Q)
	newR := new(big.Int).Add(oldR, delta)
	newR.Mod(newR, params.Q)
	if !HOAVerify(params, key.Public, newMessage, newPath, hash, newR) {
		return nil, errors.New("adapt verification failed")
	}
	return newR, nil
}

// HOATrace checks an auditable adaptation transcript. It does NOT recover a
// CA identifier from collisions. That protocol-specific trace construction
// must be specified and reviewed separately.
func HOATrace(params *HOAParameters, public *big.Int, oldMessage, oldPath, newMessage, newPath []byte, hash, oldR, newR *big.Int) bool {
	return HOAVerify(params, public, oldMessage, oldPath, hash, oldR) && HOAVerify(params, public, newMessage, newPath, hash, newR)
}
