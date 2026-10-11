package hoa

import (
	"crypto/rand"
	"errors"
	"math/big"
)

type Share struct {
	X int    `json:"x"`
	Y string `json:"y"`
}

// SplitSecret creates independent Shamir shares in Z_q. Shares must stay off-chain.
func SplitSecret(secret, q *big.Int, n, k int) ([]Share, error) {
	if q == nil || !q.ProbablyPrime(64) || secret == nil || secret.Sign() < 0 || secret.Cmp(q) >= 0 || k < 2 || n < k || n > 65535 || big.NewInt(int64(n)).Cmp(q) >= 0 {
		return nil, errors.New("invalid sharing parameters")
	}
	coeff := make([]*big.Int, k)
	coeff[0] = new(big.Int).Set(secret)
	for i := 1; i < k; i++ {
		v, e := rand.Int(rand.Reader, q)
		if e != nil {
			return nil, e
		}
		coeff[i] = v
	}
	res := make([]Share, n)
	for i := 1; i <= n; i++ {
		x := big.NewInt(int64(i))
		y := new(big.Int).Set(coeff[k-1])
		for j := k - 2; j >= 0; j-- {
			y.Mul(y, x)
			y.Add(y, coeff[j])
			y.Mod(y, q)
		}
		res[i-1] = Share{X: i, Y: y.Text(16)}
	}
	return res, nil
}
func RecoverSecret(shares []Share, q *big.Int, k int) (*big.Int, error) {
	if q == nil || !q.ProbablyPrime(64) || k < 2 || len(shares) < k {
		return nil, errors.New("invalid recovery parameters")
	}
	used := map[int]bool{}
	sum := new(big.Int)
	for i := 0; i < k; i++ {
		s := shares[i]
		if s.X <= 0 || used[s.X] {
			return nil, errors.New("invalid or duplicate share index")
		}
		used[s.X] = true
		yi, ok := new(big.Int).SetString(s.Y, 16)
		if !ok || yi.Sign() < 0 || yi.Cmp(q) >= 0 || big.NewInt(int64(s.X)).Cmp(q) >= 0 {
			return nil, errors.New("invalid share value")
		}
		term := new(big.Int).Set(yi)
		for j := 0; j < k; j++ {
			if j == i {
				continue
			}
			xj := big.NewInt(int64(shares[j].X))
			xi := big.NewInt(int64(s.X))
			if xj.Sign() <= 0 || xj.Cmp(q) >= 0 {
				return nil, errors.New("invalid index")
			}
			num := new(big.Int).Neg(xj)
			num.Mod(num, q)
			den := new(big.Int).Sub(xi, xj)
			den.Mod(den, q)
			inv := new(big.Int).ModInverse(den, q)
			if inv == nil {
				return nil, errors.New("noninvertible share index")
			}
			term.Mul(term, num)
			term.Mod(term, q)
			term.Mul(term, inv)
			term.Mod(term, q)
		}
		sum.Add(sum, term)
		sum.Mod(sum, q)
	}
	return sum, nil
}
