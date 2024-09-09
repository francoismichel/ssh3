package main

import (
	"github.com/francoismichel/ssh3/cmd"
	"os"

	// authentication plugins
	_ "github.com/francoismichel/ssh3/auth/plugins/pubkey_authentication/client"
  _ "github.com/francoismichel/ssh3/auth/plugins/openpubkey/client"
)

func main() {
	os.Exit(cmd.ClientMain())
}
