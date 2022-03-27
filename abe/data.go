package abe

import (
	//ec "github.com/cloudflare/circl/ecc/bls12381"
	"github.com/cloudflare/circl/ecc/bls12381/ff"
)

// This is a set of attested facts, including the signer key
type Certificate struct {
	Signer []byte            `json:"signer"`
	Facts  map[string][]byte `json:"facts"`
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
