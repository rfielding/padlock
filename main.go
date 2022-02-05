package main

import (
	"encoding/json"
	"fmt"
	"log"
)

func AsSpec(s string) (Spec, error) {
	var e Spec
	err := json.Unmarshal([]byte(s), &e)
	if err != nil {
		return e, fmt.Errorf("parse error: %v", err)
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
	Label      string          `json:"label"`
	Foreground string          `json:"fg,omitempty"`
	Background  string          `json:"bg,omitempty"`
	Cases      map[string]Case `json:"cases"`
}

type Case struct {
	Keys []string `json:"keys"`
	Expr Expr     `json:"expr"`
}

type Expr struct {
	And       []Expr   `json:"and,omitempty"`
	Or        []Expr   `json:"or,omitempty"`
	Is        string   `json:"is,omitempty"`
	Some      []string `json:"some,omitempty"`
	Every     []string `json:"every,omitempty"`
	Requires string   `json:"requires,omitempty"`
}

func (s Spec) Normalize() (Spec, error) {
	r := Spec{}
	r.Label = s.Label
	r.Foreground = s.Foreground
	r.Background = s.Background
	r.Cases = make(map[string]Case)
	for k, v := range s.Cases {
		n, err := s.Cases[k].Expr.Norm(s.Cases)
		if err != nil {
			return s, err
		}
		// Make the case into Or over And
		if len(n.Or) > 0 {
			r.Cases[k] = Case{
				Keys: v.Keys, 
				Expr: n,
			}
			continue
		}
		// If it's And, wrap it in Or
		if len(n.And) > 0 {
			r.Cases[k] = Case{
				Keys: v.Keys,
				Expr: Expr{
					Or: []Expr{n},
				},
			}
			continue
		}
		// If it's Is, wrap it in Or over And
		if len(n.Is) > 0 {
			r.Cases[k] = Case{
				Keys: v.Keys,
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
		return r,fmt.Errorf("spec validation: should be one of Or,And,Is,Some,Every")
	}
	return r, nil
}


func (e Expr) Norm(cases map[string]Case) (Expr, error) {
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
	if consistency != 1 {
		return e, fmt.Errorf("invalid expression: must be op Is,And,Or,Requires,Some,Every")
	}

	if len(e.Requires) > 0 {
		v,ok := cases[e.Requires]
		if !ok {
			return e, fmt.Errorf("invalid expression: op Requires not found")
		}
		v2,err := v.Expr.Norm(cases)
		if !ok {
			return e, fmt.Errorf("invalid expression: cannot normalize Requires: %v",err)
		}
		return v2, nil
	}

	// Atomic term.  Just return it
	if len(e.Is) > 0 {
		return e, nil
	}

	r := Expr{}
	if len(e.Every) > 0 {
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

	r = Expr{}
	if len(e.Some) > 0 {
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


	// Normalize all Or args
	r = Expr{}
	for i := range e.Or {
		n, err := e.Or[i].Norm(cases)
		if err != nil {
			return r, err
		}
		r.Or = append(r.Or, n)
	}
	if len(r.Or) > 0 {
		return r.FlatOr(), nil
	}

	if len(e.And) == 0 {
		return r, fmt.Errorf("invalid expression: should be And term")
	}
	
	// Normalize all And args
	r = Expr{}
	for i := range e.And {
		n, err := e.And[i].Norm(cases)
		if err != nil {
			return r, err
		}
		r.And = append(r.And, n)
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
	r3 := Expr{}
	for i := 0; i < len(r2.Or); i++ {
		r3.Or = append(r3.Or, r2.Or[i].FlatAnd())
	}
	return r3, nil
}

func (e Expr) FlatAnd() Expr {
	if len(e.And) > 0 {
		r := Expr{}
		for i := 0 ; i < len(e.And); i++ {
			if len(e.And[i].And) > 0 {
				for j := 0; j < len(e.And[i].And); j++ {
					r.And = append(r.And, e.And[i].And[j])
				}
			} else {
				r.And = append(r.And, e.And[i])
			}
		}
		return r
	}
	return e
}

func (e Expr) FlatOr() Expr {
	if len(e.Or) > 0 {
		r := Expr{}
		for i := 0 ; i < len(e.Or); i++ {
			if len(e.Or[i].Or) > 0 {
				for j := 0; j < len(e.Or[i].Or); j++ {
					r.Or = append(r.Or, e.Or[i].Or[j])
				}
			} else {
				r.Or = append(r.Or, e.Or[i])
			}
		}
		return r
	}
	return e
}


func main() {
	e, err := AsSpec(`{
		"label": "ADULT",
		"fg": "white",
		"bg": "black",
		"cases": {
			"isAdultCit": {
				"keys": ["R"],
				"expr": {
					"and": [
						{"some": ["citizenship", "US", "NL"]},
						{"every": ["age", "adult", "driving"]}
					]
				}
			},
			"isOwner": {
				"keys": ["W","R"],
				"expr": {
					"and": [
						{"requires": "isAdultCit"},
						{"some": ["email","rob.fielding@gmail.com","rrr00bb@yahoo.com"]}
					]
				}
			}
		}
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
