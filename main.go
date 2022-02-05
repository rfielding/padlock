package main

import (
	"encoding/json"
	"fmt"
	"log"
)

func AsExpr(s string) (Expr,error) {
	var e Expr
	err := json.Unmarshal([]byte(s), &e)
	if err != nil {
		return e, fmt.Errorf("parse error: %v", err)
	}
	return e,nil
}

func AsJson(v interface{}) string {
	j, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		log.Printf("Unable to marshal to json: %v", v)
	}
	return string(j)
}

/*
  example:

 {"and": [{"or": [{"is":"squirrel"},{"is":"moose"}]}, {"is":"secret"}]}
*/
type Expr struct {
	And []Expr `json:"and,omitempty"`
	Or  []Expr `json:"or,omitempty"`
	Is  string `json:"is,omitempty"`
	Some []string `json:"some,omitempty"`
	Every []string `json:"every,omitempty"`
}

func (e Expr) Normalize() (Expr,error) {
	r := Expr{}
	n, err := e.Norm()
	if err != nil {
		return n, err
	}
	if len(n.Or) > 0 {
		for i := 0; i < len(n.Or); i++ {
			nn, err := n.Or[i].Norm()
			if err != nil {
				return nn, err
			}
			r.Or = append(
				r.Or,
				nn,
			)
		}
		return n,nil
	}
	if len(n.And) > 0 {
		return Expr{
			Or: []Expr{n},
		},nil
	}
	if len(n.Is) > 0 {
		return Expr{
			Or: []Expr{
				Expr{
					And: []Expr{
						Expr{Is: n.Is},
					},
				},
			},
		},nil
	}
	return Expr{},fmt.Errorf("invalid expression: must be made of And,Or,Some,Every,Is")
}

func (e Expr) Norm() (Expr,error) {
	r := Expr{}

	if len(e.Is) > 0 && len(e.And) > 0 {
		return r, fmt.Errorf("invalid expression: cant be Is,And at the same time")
	}
	if len(e.Or) > 0 && len(e.And) > 0 {
		return r, fmt.Errorf("invalid expression: cant be Or,And at the same time")
	}
	if len(e.Or) > 0 && len(e.Is) > 0 {
		return r, fmt.Errorf("invalid expression: cant be Or,Is at the same time")
	}

	if len(e.Every) > 0 {
		if len(e.Every) == 1 {
			return r, fmt.Errorf("invalid expression: op Eevery requires first value is a field")
		}
		f := e.Every[0]
		a := e.Every[1:]
		for i := 0; i < len(a); i++ {
			v := Expr{Is: fmt.Sprintf("%s:%s", f, a[i])}
			r.And = append(r.And, v)
		}
		return r, nil
	}
	if len(e.Some) > 0 {
		if len(e.Some) == 1 {
			return r, fmt.Errorf("invalid expression: op Some requires first value is a field")
		}
		f := e.Some[0]
		a := e.Some[1:]
		for i := 0; i < len(a); i++ {
			v := Expr{Is: fmt.Sprintf("%s:%s", f, a[i])}
			r.Or = append(r.Or, v)
		}
		return r, nil
	}

	// Atomic term.  Just return it
	if len(e.Is) > 0 {
		return e, nil
	}

	// Normalize all Or args
	for i := range e.Or {
		n, err := e.Or[i].Norm()
		if err != nil {
			return r,err
		}
		r.Or = append(r.Or, n)
	}
	if len(e.Or) > 0 {
		return r, nil
	}

	if len(e.And) == 0 {
		return r, fmt.Errorf("invalid expression: should be And term")
	}
	// Normalize all And args
	for i := range e.And {
		n, err := e.And[i].Norm()
		if err != nil {
			return r, err
		}
		r.And = append(r.And,n)
	}

	// If there is more than one, then combine as much as possible,
	// eliminating first arg as we do so
	r2 := Expr{}
	for k := 0; k < len(r.And); k++ {
		rak := r.And[k]
		// Get started with the leftmost item
		if k == 0 {
			if len(rak.Or) > 0 {
				for j := 0; j < len(rak.Or); j++ {
					r2.Or = append(
						r2.Or,
						rak.Or[j],
					)
				}
				continue
			}
			r2.Or = append(
				r2.Or,
				rak,
			)
			continue
		}
		// Handle the or case
		if len(rak.Is) > 0 {
			r3 := Expr{}
			for i := 0; i < len(r2.Or); i++ {
				r3.Or = append(
					r3.Or,
					Expr{And: []Expr{r2.Or[i], rak}},
				)
			}
			r2 = r3
			continue
		}
		// Handle the or case
		if len(r.And[k].And) > 0 {
			r3 := Expr{}
			for i := 0; i < len(r2.Or); i++ {
				r3.Or = append(
					r3.Or,
					Expr{And: append([]Expr{r2.Or[i]}, rak.And...)},
				)
			}
			r2 = r3
			continue
		}
		// Handle the or case
		if len(rak.Or) > 0 {
			r3 := Expr{}
			for i := 0; i < len(r2.Or); i++ {
				for j := 0; j < len(rak.Or); j++ {
					r3.Or = append(
						r3.Or,
						Expr{And: []Expr{r2.Or[i], rak.Or[j]}},
					)
				}
			}
			r2 = r3
			continue
		}
	}
	return r2,nil
}

func main() {
	e,err := AsExpr(`{
		"and": [
			{"some": ["citizenship", "US", "NL", "UK"]},
			{"every": ["age", "adult", "driving"]}
		]
	}`)
	if err != nil {
		panic(err)
	}
	n, err := e.Normalize()
	if err != nil {
		panic(err)
	}
	fmt.Printf("e: %s\n", AsJson(e))
	fmt.Printf("eN: %s\n", AsJson(n))
}
