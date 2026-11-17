package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/Mininglamp-OSS/octo-cli/cmd"
	"github.com/Mininglamp-OSS/octo-cli/internal/cmdutil"
)

func main() {
	os.Exit(run())
}

func run() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	f := cmdutil.NewDefaultFactory()
	root := cmd.NewRootCmd(f)
	return f.ExitCode(root.ExecuteContext(ctx))
}
