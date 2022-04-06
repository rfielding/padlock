package abe

import (
	//"github.com/cloudflare/circl/group"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	ec "github.com/cloudflare/circl/ecc/bls12381"
	"github.com/cloudflare/circl/ecc/bls12381/ff"
	"log"
	"sort"
)

// !!! Problem: this curve keeps x,y,z members private, so I can't extract them
// !!! I will need another way to blind the certificates
// L[v] = sum_j [ Y_j * prod_i^{i != j}[(x - x_j)/(x_i - x_j)]
func Lagrange(v *ff.Scalar, x []*ff.Scalar, y []*ff.Scalar) *ff.Scalar {
	sum := new(ff.Scalar)
	for j := 0; j < len(y); j++ {
		prod := new(ff.Scalar)
		prod.SetOne()
		prod.Mul(prod, y[j])
		for i := 0; i < len(x); i++ {
			if i != j {
				num := new(ff.Scalar)
				num.Sub(v, x[j])
				div := new(ff.Scalar)
				div.Sub(x[i], x[j])
				div.Inv(div)
				prod.Mul(prod, num)
				prod.Mul(prod, div)
			}
		}
		sum.Add(sum, prod)
	}
	return sum
}

func (c *Certificate) Cert() (*ec.G2, error) {
	p := ec.G2Generator()
	err := p.SetBytes(c.Signer)
	if err != nil {
		return nil, fmt.Errorf("Cannot decode signer: %v", err)
	}
	return p, nil
}

// Issue a certificate by calculating a map from known values to signed points,
// where unknown values map to arbitrary points.
func Issue(s *ff.Scalar, facts []string) (Certificate, error) {
	// facts signed like:    (s-u)H1(f_i)
	// unwrap is like: (s/(s-u))*G2
  u := R()
	sMinusU := new(ff.Scalar)
	sMinusU.SetOne()
	sMinusU.Mul(sMinusU, s)
	sMinusU.Sub(sMinusU, u)

  div := new(ff.Scalar)
	div.Inv(sMinusU)
	sDivsMinusU := new(ff.Scalar)
	sDivsMinusU.SetOne()
	sDivsMinusU.Mul(sDivsMinusU, s)
	sDivsMinusU.Mul(sDivsMinusU, div)
	unwrapBytes := CA(sDivsMinusU).Bytes()

	// sign with bytes (priv-u)
	pubBytes := CA(s).Bytes()
	cert := Certificate{
		Signer: pubBytes,
		Unwrap: unwrapBytes,
		Facts:  make(map[string][]byte),
	}
	for j := 0; j < len(facts); j++ {
		cert.Facts[facts[j]] = H1n(facts[j],sMinusU).Bytes()
	}
	return cert, nil
}

func H1(s string) *ec.G1 {
	v := ec.G1Generator()
	v.Hash([]byte(s), nil)
	return v
}

func H1n(s string, n *ff.Scalar) *ec.G1 {
	v := ec.G1Generator()
	v.Hash([]byte(s), nil)
	v.ScalarMult(n, v)
	return v
}

func Hsb(b []byte) *ff.Scalar {
	h := sha256.Sum256(b)
	k := new(ff.Scalar)
	k.SetBytes(h[:])
	return k
}
func Hs(s string) *ff.Scalar {
	h := sha256.Sum256([]byte(s))
	k := new(ff.Scalar)
	k.SetBytes(h[:])
	return k
}

func S(s *ff.Scalar, p *ec.G1) *ec.G1 {
	g := ec.G1Generator()
	g.ScalarMult(s, p)
	return g
}

func R() *ff.Scalar {
	r := new(ff.Scalar)
	r.Random(rand.Reader)
	return r
}

func CA(s *ff.Scalar) *ec.G2 {
	q := ec.G2Generator()
	q.ScalarMult(s, q)
	return q
}

// The array of G1 are secret*H1(attr), and b is what to pair it with
func G1SumPairXor(signedFacts []*ec.G1, b *ec.G2, k []byte) ([]byte, error) {
	p := new(ec.G1)
	// Get a sum of the required attributes
	for j := 0; j < len(signedFacts); j++ {
		p.Add(p, signedFacts[j])
	}
	v, err := ec.Pair(p, b).MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("ec.Pair(p.f).MarshalBinary: %v", err)
	}
	return Xor(k, v), nil
}

func AsSpec(s string, capub *ec.G2, targets map[string][]byte) (Spec, error) {
	// Parse the lock specification
	var sp Spec
	err := json.Unmarshal([]byte(s), &sp)
	if err != nil {
		return sp, fmt.Errorf("parse error: %v", err)
	}
	sp, err = sp.Normalize()
	if err != nil {
		return sp, err
	}
	sp.Blueprint = s
	// Pair(sum_i[ f H1(a_i)], pub)
	for u, _ := range sp.Unlocks {
		f := R()
		fileFacts := make([]*ec.G1, 0) // [] f*H1(attr_i) * s
		for i := 0; i < len(sp.Unlocks[u].And); i++ {
			fileFacts = append(fileFacts, H1n(sp.Unlocks[u].And[i], f))
		}

		answer, err := G1SumPairXor(fileFacts, capub, targets[sp.Unlocks[u].Key])
		if err != nil {
			return sp, fmt.Errorf("G1SumPairXor: %v", err)
		}
		sp.Unlocks[u].K = answer

    sp.Unlocks[u].F = f
	}
	sp.CAPub = capub.Bytes()
	return sp, nil
}

// Plug in a certificate and see what keys come back
func (sp *Spec) Unlock(cert Certificate) (map[string][]byte, error) {
	granted := make(map[string][]byte)
	capub := ec.G2Generator()
	err := capub.SetBytes(sp.CAPub)
	if err != nil {
		return granted, fmt.Errorf("capub.SetBytes(s.Unlocks[u].Pubf): %v", err)
	}
	for u, _ := range sp.Unlocks {
		// Are all the facts we need in here?
		hasAll := true
		for i := 0; i < len(sp.Unlocks[u].And); i++ {
			_, ok := cert.Facts[sp.Unlocks[u].And[i]]
			if !ok {
				hasAll = false
			}
		}
		if hasAll {
			signedAttrs := make([]*ec.G1, 0) // [] s*H1(attr_i)
			for i := 0; i < len(sp.Unlocks[u].And); i++ {
				v := cert.Facts[sp.Unlocks[u].And[i]]
				val := ec.G1Generator()
				err := val.SetBytes(v)
				if err != nil {
					return nil, fmt.Errorf("val.SetBytes(v): %v", err)
				}
				signedAttrs = append(signedAttrs, val) // [] s*H1(atr_i) * f
			}
			unwrap := ec.G2Generator()
			err := unwrap.SetBytes(cert.Unwrap)
			if err != nil {
				return nil, fmt.Errorf("filepub.SetBytes: %v", err)
			}
			f := sp.Unlocks[u].F
			unwrap.ScalarMult(f, unwrap)
			answer, err := G1SumPairXor(signedAttrs, unwrap, sp.Unlocks[u].K)
			if err != nil {
				return nil, fmt.Errorf("G1SumPairXor: %v", err)
			}
			granted[sp.Unlocks[u].Key] = answer
		}
	}
	return granted, nil
}

func Xor(t []byte, k []byte) []byte {
	v := make([]byte, len(t))
	for i := 0; i < len(t); i++ {
		v[i] = t[i] ^ k[i]
	}
	return v
}

func AsJson(v interface{}) string {
	j, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		log.Printf("Unable to marshal to json: %v", v)
	}
	return string(j)
}

func (s Spec) Normalize() (Spec, error) {
	r := Spec{}
	r.Label = s.Label
	r.Foreground = s.Foreground
	r.Background = s.Background
	r.Cases = make(map[string]Case)
	for k, v := range s.Cases {
		n, err := s.Cases[k].Expr.Flat(s.Cases)
		if err != nil {
			return s, err
		}
		// Make the case into Or over And
		if len(n.Or) > 0 {
			r.Cases[k] = Case{
				Key:  v.Key,
				Expr: n,
			}
			continue
		}
		// If it's And, wrap it in Or
		if len(n.And) > 0 {
			r.Cases[k] = Case{
				Key: v.Key,
				Expr: Expr{
					Or: []Expr{n},
				},
			}
			continue
		}
		// If it's Is, wrap it in Or over And
		if len(n.Is) > 0 {
			r.Cases[k] = Case{
				Key: v.Key,
				Expr: Expr{
					Or: []Expr{
						Expr{
							And: []Expr{
								Expr{Is: n.Is},
							},
						},
					},
				},
			}
			continue
		}
		return r, fmt.Errorf("spec validation: should be one of Or,And,Is,Some,Every")
	}
	// Flatten out the Or over And over Is per Keys, into list of Keys,List[Is]
	for k, _ := range r.Cases {
		for i := 0; i < len(r.Cases[k].Expr.Or); i++ {
			items := make([]string, 0)
			a := r.Cases[k].Expr.Or[i].FlatAnd()
			for j := 0; j < len(a.And); j++ {
				v := a.And[j].Is
				items = append(items, v)
				if len(v) == 0 {
					return r, fmt.Errorf(
						"error in normalization of spec: %v",
						AsJson(r.Cases[k].Expr.Or[i]),
					)
				}
			}
			r.Unlocks = append(
				r.Unlocks,
				Unlock{
					Key: r.Cases[k].Key,
					And: items,
				},
			)
		}
	}
	r.Cases = nil
	return r, nil
}

func (e Expr) IsConsistent() bool {
	// Bomb out if it's not a single kind
	consistency := 0
	if len(e.Is) > 0 {
		consistency++
	}
	if len(e.And) > 0 {
		consistency++
	}
	if len(e.Or) > 0 {
		consistency++
	}
	if len(e.Requires) > 0 {
		consistency++
	}
	if len(e.Some) > 0 {
		consistency++
	}
	if len(e.Every) > 0 {
		consistency++
	}
	return consistency == 1
}

func (e Expr) FlatDistribute(cases map[string]Case) (Expr, error) {
	hasAnOr := false
	for k := 0; k < len(e.And); k++ {
		if len(e.And[k].Or) > 0 {
			hasAnOr = true
		}
	}
	if !hasAnOr {
		return e, nil
	}
	r := Expr{}
	k := 0
	eak := e.And[k]
	if len(eak.Or) > 0 {
		for j := 0; j < len(eak.Or); j++ {
			r.Or = append(
				r.Or,
				eak.Or[j],
			)
		}
	} else {
		r.Or = append(
			r.Or,
			eak,
		)
	}
	for k = 1; k < len(e.And); k++ {
		eak = e.And[k]
		// Get started with the leftmost item
		r3 := Expr{}
		if len(eak.Is) > 0 {
			for i := 0; i < len(r.Or); i++ {
				r3.Or = append(
					r3.Or,
					Expr{And: []Expr{r.Or[i], eak}},
				)
			}
		} else if len(eak.And) > 0 {
			for i := 0; i < len(r.Or); i++ {
				for j := 0; j < len(eak.And); j++ {
					v := eak.And[j]
					r3.Or = append(
						r3.Or,
						Expr{And: append([]Expr{r.Or[i]}, v)},
					)
				}
			}
		} else if len(eak.Or) > 0 {
			for i := 0; i < len(r.Or); i++ {
				for j := 0; j < len(eak.Or); j++ {
					r3.Or = append(
						r3.Or,
						Expr{And: []Expr{r.Or[i], eak.Or[j]}},
					)
				}
			}
		}
		r = r3
	}
	return r, nil
}

func (e Expr) Flat(cases map[string]Case) (Expr, error) {
	var err error
	if !e.IsConsistent() {
		return e, fmt.Errorf("invalid expression: must be op Is,And,Or,Requires,Some,Every")
	}

	if len(e.Requires) > 0 {
		c, ok := cases[e.Requires]
		if !ok {
			return e, fmt.Errorf("invalid expression: op Requires not found")
		}
		e, err = c.Expr.Flat(cases)
		if !ok {
			return e, fmt.Errorf("invalid expression: cannot normalize Requires: %v", err)
		}
		return e, nil
	}

	if len(e.Some) > 0 {
		r := Expr{}
		if len(e.Some) == 1 {
			return e, fmt.Errorf("invalid expression: op Some requires first value is a field")
		}
		f := e.Some[0]
		a := e.Some[1:]
		for i := 0; i < len(a); i++ {
			v := Expr{Is: fmt.Sprintf("%s:%s", f, a[i])}
			r.Or = append(r.Or, v)
		}
		return r, nil
	}

	if len(e.Every) > 0 {
		r := Expr{}
		if len(e.Every) == 1 {
			return e, fmt.Errorf("invalid expression: op Eevery requires first value is a field")
		}
		f := e.Every[0]
		a := e.Every[1:]
		for i := 0; i < len(a); i++ {
			v := Expr{Is: fmt.Sprintf("%s:%s", f, a[i])}
			r.And = append(r.And, v)
		}
		return r, nil
	}

	// And may convert to Or or Is and fall through
	if len(e.And) > 0 {
		// Normalize args
		r := Expr{}
		for i := range e.And {
			n, err := e.And[i].Flat(cases)
			if err != nil {
				return e, fmt.Errorf("e.And[i].Flat(cases): %v", err)
			}
			r.And = append(r.And, n)
		}
		// Sort with And > Or to make them adjacent
		sort.Slice(r.And, func(i, j int) bool {
			return len(r.And[i].And) > 0 && len(r.And[j].Or) > 0
		})

		r, err = r.FlatDistribute(cases)
		if err != nil {
			return r, fmt.Errorf("r.FlatDistribute(cases): %v", err)
		}

		// It could be And or Or or Is at this point
		if len(r.Or) > 0 {
			// flatten out and
			for i := 0; i < len(r.Or); i++ {
				r.Or[i] = r.Or[i].FlatAnd()
			}
			return r, err
		} else if len(r.And) > 0 {
			e = r.FlatAnd()
		} else if len(r.Is) > 0 {
			e = r
		}
	}

	if len(e.Is) > 0 {
		return e, nil
	}

	if len(e.Or) > 0 {
		r := Expr{}
		for i := range e.Or {
			n, err := e.Or[i].Flat(cases)
			if err != nil {
				return e, fmt.Errorf("e.Or[i].Flat(cases): %v", err)
			}
			r.Or = append(r.Or, n)
		}
		sort.Slice(r.Or, func(i, j int) bool {
			return len(r.Or[i].And) > 0 && len(r.Or[j].Or) > 0
		})
		return r, nil
	}

	return e, fmt.Errorf("unrecotnized expression")
}

func (e Expr) FlatOr() Expr {
	if len(e.Or) > 0 {
		r := Expr{}
		for i := 0; i < len(e.Or); i++ {
			if len(e.Or[i].Or) > 0 {
				for j := 0; j < len(e.Or[i].Or); j++ {
					r.Or = append(r.Or, e.Or[i].Or[j])
				}
			} else if len(e.Or[i].And) > 0 {
				r.Or = append(r.Or, e.Or[i].FlatAnd())
			} else {
				r.Or = append(r.Or, e.Or[i])
			}
		}
	}
	return e
}

func (e Expr) FlatAnd() Expr {
	if len(e.And) > 0 {
		r := Expr{}
		for i := 0; i < len(e.And); i++ {
			if len(e.And[i].And) > 0 {
				for j := 0; j < len(e.And[i].And); j++ {
					r.And = append(r.And, e.And[i].And[j].FlatAnd())
				}
			} else if len(e.And[i].Or) > 0 {
				r.And = append(r.And, e.And[i].FlatOr())
			} else {
				r.And = append(r.And, e.And[i])
			}
		}
		return r
	}
	return e
}
