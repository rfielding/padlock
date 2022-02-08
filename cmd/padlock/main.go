package main

import (
	//"github.com/cloudflare/circl/group"
	"encoding/json"
	"fmt"
	ec "github.com/cloudflare/circl/ecc/bls12381"
	"github.com/cloudflare/circl/ecc/bls12381/ff"
	"log"
	"sort"
	//"math/big"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
)

func H1(s string) *ec.G1 {
	v := ec.G1Generator()
	v.Hash([]byte(s), nil)
	return v
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

func AsSpec(s string, pub *ec.G2, targets map[string][32]byte) (Spec, error) {
	// Parse the lock specification
	var e Spec
	err := json.Unmarshal([]byte(s), &e)
	if err != nil {
		return e, fmt.Errorf("parse error: %v", err)
	}
	e.Targets = targets
	e, err = e.Normalize()
	if err != nil {
		return e, err
	}
	// Pair(sum_i[ f H1(a_i)], pub)
	f := R()
	for u, _ := range e.Unlocks {
		p := ec.G1Generator()
		for i := 0; i < len(e.Unlocks[u].And); i++ {
			p.Add(p, H1(e.Unlocks[u].And[i]))
			p.ScalarMult(f, p)
		}
		pt := ec.Pair(p, pub)
		// xor this secret with the target
		e.Unlocks[u].Pt = []byte(Hs(pt.String()).String())
		e.Unlocks[u].Pf = p
		fmt.Printf("\n%v %s:\n%s\n%v\n", e.Unlocks[u].And,e.Unlocks[u].Key,hex.EncodeToString(e.Unlocks[u].Pt))
	}
	return e, nil
}

func AsJson(v interface{}) string {
	j, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		log.Printf("Unable to marshal to json: %v", v)
	}
	return string(j)
}

type Spec struct {
	Label      string              `json:"label"`
	Foreground string              `json:"fg,omitempty"`
	Background string              `json:"bg,omitempty"`
	Cases      map[string]Case     `json:"cases,omitempty"`
	Unlocks    []Unlock            `json:"unlocks,omitempty"`
	Targets    map[string][32]byte `json:"-"`
	Pub        *ec.G2              `json:"pub,omitempty"`
}

type Unlock struct {
	Key string   `json:"key,omitempty"`
	And []string `json:"and,omitempty"`
	Pt  []byte   `json:"pt,omitempty"`
	Pf  *ec.G1   `json:"pf,omitempty"`
}

type Case struct {
	Diff *ff.Scalar `json:"diff"`
	Key  string     `json:"key"`
	Expr Expr       `json:"expr"`
}

type Expr struct {
	And      []Expr   `json:"and,omitempty"`
	Or       []Expr   `json:"or,omitempty"`
	Is       string   `json:"is,omitempty"`
	Some     []string `json:"some,omitempty"`
	Every    []string `json:"every,omitempty"`
	Requires string   `json:"requires,omitempty"`
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
					panic(
						fmt.Errorf(
							"error in normalization of spec: %v",
							AsJson(r.Cases[k].Expr.Or[i]),
						),
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
				return e, err
			}
			r.And = append(r.And, n)
		}
		// Sort with And > Or to make them adjacent
		sort.Slice(r.And, func(i, j int) bool {
			return len(r.And[i].And) > 0 && len(r.And[j].Or) > 0
		})

		r, err = r.FlatDistribute(cases)
		if err != nil {
			return r, err
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
				return e, err
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

func main() {
	s := Hs("farkfark")
	pub := CA(s)
	W := sha256.Sum256([]byte("pencil"))
	R := sha256.Sum256([]byte("paper"))
	e, err := AsSpec(`{
		"label": "ADULT",
		"fg": "white",
		"bg": "black",
		"cases": {
			"isOwner": {
				"key": "W",
				"expr": {
					"and": [
						{"requires": "isAdultCit"},
						{"some": ["email","rob.fielding@gmail.com","rrr00bb@yahoo.com"]}
					]
				}
			},
			"isAdultCit": {
				"key": "R",
				"expr": {
					"and": [
						{"some": ["citizenship", "US", "NL"]},
						{"every": ["citizenship", "!NK"]},
						{"every": ["age", "adult", "driving"]}
					]
				}
			}
		}
	}`, pub, map[string][32]byte{
		"W": W,
		"R": R,
	})

	if err != nil {
		panic(err)
	}
	fmt.Printf("eN: %s\n", AsJson(e))
}
