package main

import (
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/term"
)

func Signals() {
	prev, err := term.GetState(int(os.Stdin.Fd()))
	if err != nil {
		prev = nil
	}

	s := make(chan os.Signal, 1)
	signal.Notify(s, syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT)
	for range s {
		term.Restore(int(os.Stdin.Fd()), prev)
		os.Exit(1)
	}
}
