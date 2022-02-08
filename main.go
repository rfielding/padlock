package main

import (
	"sort"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
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
	Cases      map[string]Case `json:"cases,omitempty"`
	Unlocks []Unlock `json:"unlocks,omitempty"`
}

type Unlock struct {
	Key string `json:"key,omitempty"`
	And []string `json:"and,omitempty"`
}

type Case struct {
	Diff big.Int `json:"diff"`
	Key string `json:"key"`
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
				Key: v.Key, 
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
		return r,fmt.Errorf("spec validation: should be one of Or,And,Is,Some,Every")
	}
	// Flatten out the Or over And over Is per Keys, into list of Keys,List[Is]
	for k,_ := range r.Cases{
		for i := 0; i < len(r.Cases[k].Expr.Or); i++ {
			items := make([]string,0)
			for j := 0; j < len(r.Cases[k].Expr.Or[i].And); j++ {
				v := r.Cases[k].Expr.Or[i].And[j].Is
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


func (e Expr) Norm(cases map[string]Case) (Expr, error) {
	var err error

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
		c,ok := cases[e.Requires]
		if !ok {
			return e, fmt.Errorf("invalid expression: op Requires not found")
		}
		e,err = c.Expr.Norm(cases)
		if !ok {
			return e, fmt.Errorf("invalid expression: cannot normalize Requires: %v",err)
		}
		return e, nil
	}

	// Atomic term.  Just return it
	if len(e.Is) > 0 {
		return e, nil
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


	// It's recursive And and Or from here out
	// Normalize e
	r := Expr{ }

	if len(e.And) > 0 {
		for i := range e.And {
			n, err := e.And[i].Norm(cases)
			if err != nil {
				return e, err
			}
			r.And = append(r.And, n)
		}
		sort.Slice(r.And, func(i,j int) bool {
			return len(r.And[i].And) > 0 && len(r.And[j].Or) > 0 
		})
		rf := Expr{}
		for i := 0 ; i < len(r.And); i++ {
			if len(r.And[i].And) > 0 {
				for j := 0 ; j < len(r.And[i].And); j++ {
					rf.And = append(rf.And, r.And[i].And[j])
				}
			} else {
				rf.And = append(rf.And, r.And[i])
			}
		}
		r = rf
	}

	if len(e.Or) > 0 {
		for i := range e.Or {
			n, err := e.Or[i].Norm(cases)
			if err != nil {
				return e, err
			}
			r.Or = append(r.Or, n)
		}
		sort.Slice(r.Or, func(i,j int) bool {
			return len(r.Or[i].And) > 0 && len(r.Or[j].Or) > 0 
		})
		rf := Expr{}
		for i := 0 ; i < len(r.Or); i++ {
			if len(r.Or[i].Or) > 0 {
				for j := 0 ; j < len(r.Or[i].Or); j++ {
					rf.Or = append(rf.Or, r.Or[i].Or[j])
				}
			} else {
				rf.Or = append(rf.Or, r.Or[i])
			}
		}
		r = rf
		return r, nil
	}

	if len(e.And) == 0 {
		return e, fmt.Errorf("should be And for this term")
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
	/*
	return r2,nil
	*/
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
						{"every": ["age", "adult", "driving"]}
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
