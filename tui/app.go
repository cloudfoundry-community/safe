package tui

import (
	"fmt"
	"log"
	"os"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/cloudfoundry-community/safe/rc"
	"github.com/cloudfoundry-community/safe/tui/model"
)

// Run starts the TUI application
func Run(args ...string) error {
	// Set up debug log file (for troubleshooting)
	if logFile, err := os.OpenFile("/tmp/safe-tui-debug.log", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644); err == nil {
		log.SetOutput(logFile)
		log.SetFlags(log.Ltime | log.Lmicroseconds)
		log.Println("TUI starting...")
		defer logFile.Close()
	}

	// Load configuration
	cfg := rc.Read()

	// Determine initial target
	initialTarget := ""
	if len(args) > 0 {
		initialTarget = args[0]
	} else if cfg.Current != "" {
		initialTarget = cfg.Current
	}

	// Create the root model
	rootModel := model.NewRootModel(&cfg, initialTarget)

	// Create the Bubble Tea program with alt screen and mouse support
	p := tea.NewProgram(
		rootModel,
		tea.WithAltScreen(),
		tea.WithMouseCellMotion(),
	)

	// Run the program
	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error running TUI: %v\n", err)
		return err
	}

	return nil
}
