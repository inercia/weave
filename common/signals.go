package common

import (
	"os"
	"os/signal"
	"runtime"
	"syscall"
)

// A subsystem/server/... that can be stoppable when a signal is received
type SignalsStopper interface {
	Stop() error
}

func InitDefaultSignalsHandler(ss []SignalsStopper) {
    Debug.Printf("Starting the default signals handler")
    go handleSignals(ss)
}

func handleSignals(ss []SignalsStopper) {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGQUIT)
	buf := make([]byte, 1<<20)
	for {
		sig := <-sigs
		switch sig {
		case syscall.SIGINT:
			Info.Printf("=== received SIGINT ===\n*** exiting\n")
			for _, subsystem := range ss {
				subsystem.Stop()
			}
			os.Exit(0)
		case syscall.SIGQUIT:
			stacklen := runtime.Stack(buf, true)
			Info.Printf("=== received SIGQUIT ===\n*** goroutine dump...\n%s\n*** end\n", buf[:stacklen])
		}
	}
}
