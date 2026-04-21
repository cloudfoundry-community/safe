package main

import (
	"fmt"
	"os/exec"
)

type Engine interface {
	Name() string
	Binary() string
}

type vaultEngine struct{ binary string }

func (e *vaultEngine) Name() string   { return "vault" }
func (e *vaultEngine) Binary() string { return e.binary }

type baoEngine struct{ binary string }

func (e *baoEngine) Name() string   { return "bao" }
func (e *baoEngine) Binary() string { return e.binary }

func selectLocalEngine(preference string) (Engine, error) {
	if preference != "" && preference != "bao" && preference != "vault" {
		return nil, fmt.Errorf("unknown engine %q (supported: bao, vault)", preference)
	}

	order := []string{"bao", "vault"}
	if preference != "" {
		order = []string{preference}
	}

	for _, name := range order {
		path, err := exec.LookPath(name)
		if err != nil {
			continue
		}
		switch name {
		case "bao":
			return &baoEngine{binary: path}, nil
		case "vault":
			return &vaultEngine{binary: path}, nil
		}
	}

	if preference != "" {
		return nil, fmt.Errorf("%s is not installed or located in $PATH", preference)
	}
	return nil, fmt.Errorf("neither bao nor vault is installed or located in $PATH")
}
