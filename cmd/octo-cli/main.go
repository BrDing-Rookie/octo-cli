package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/Mininglamp-OSS/octo-cli/cmd"
	"github.com/Mininglamp-OSS/octo-cli/internal/cmdutil"
	"github.com/Mininglamp-OSS/octo-cli/internal/output"
)

func main() {
	os.Exit(run())
}

func run() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	f := cmdutil.NewDefaultFactory()
	root := cmd.NewRootCmd(f)
	if err := root.ExecuteContext(ctx); err != nil {
		// RunE paths mark their attempt even when stderr is blocked.
		// Only emit here for errors that bypassed the Factory.
		if !f.ErrorEmitted {
			_ = f.EmitErrorContext(ctx, err) //nolint:errcheck // best-effort write before exit
		}

		// Determine exit code from the structured error.
		ee := output.AsExitError(cmdutil.WrapCLIError(err))
		if ee == nil {
			ee = output.ErrWithHint("internal", "INTERNAL", err.Error(), "")
		}
		return ee.ExitCode()
	}
	return 0
}
