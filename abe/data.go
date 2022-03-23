package abe

import (
	"github.com/cloudflare/circl/ecc/bls12381/ff"  
)
// This is a blinded certificate that has some number
// of attributes in it.
//
// L[v] is a function that returns L[v] = (L_x[h],L_y[h]) such that h=H[v]
// This is a way to do a 1D to 2D lagrange interpolated polynomial
//
// L[v] is an oracle that answers questions correctly when it knows, and wrongly when it does not.
// Correct answers will be on the Elliptic Curve.
//
type Certificate struct {
	Facts map[string][]byte
}

type Spec struct {
  Blueprint  string          `json:"blueprint"`
	Label      string          `json:"label"`
	Foreground string          `json:"fg,omitempty"`
	Background string          `json:"bg,omitempty"`
	Cases      map[string]Case `json:"cases,omitempty"`
	Unlocks    []Unlock        `json:"unlocks,omitempty"`
	CAPub      []byte          `json:"capub,omitempty"`
}

type Unlock struct {
	Key  string   `json:"key,omitempty"`
	And  []string `json:"and,omitempty"`
	K    []byte   `json:"k,omitempty"` // The secret! needs xor vs target
	Pubf []byte   `json:"pubf,omitempty"`
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
