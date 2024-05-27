package main

import (
	"os"

	"github.com/francoismichel/ssh3/cmd"

	// authentication plugins
	_ "github.com/francoismichel/ssh3/auth/plugins/openpubkey/client"
	_ "github.com/francoismichel/ssh3/auth/plugins/pubkey_authentication/client"
)

func main() {
	os.Exit(cmd.ClientMain())
}
