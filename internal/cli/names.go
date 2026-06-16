package cli

import (
	crand "crypto/rand"
	"fmt"
	"math/big"
)

var Adjectives []string
var Nouns []string

func init() {
	Adjectives = []string{
		"hardened",
		"toughened",
		"annealed",
		"tempered",
		"fortified",
		"bastioned",
		"bolstered",
		"reinforced",
		"inviolable",
		"impregnable",
		"unassailable",
		"impervious",
		"unbreakable",
		"infrangible",
		"stalwart",
		"sturdy",
		"stouthearted",
	}

	Nouns = []string{
		"garrison",
		"fortress",
		"castle",
		"keep",
		"outpost",
		"coffer",
		"zone",
		"sanctuary",
		"refuge",
		"asylum",
		"hold",
		"oubliette",
		"donjon",
		"dungeon",
		"gaol",
	}
}

func cryptoRandInt(max int) int {
	nBig, err := crand.Int(crand.Reader, big.NewInt(int64(max)))
	if err != nil {
		panic(err)
	}
	return int(nBig.Int64())
}

func RandomName() string {
	return fmt.Sprintf("%s-%s",
		Adjectives[cryptoRandInt(len(Adjectives))],
		Nouns[cryptoRandInt(len(Nouns))])
}
