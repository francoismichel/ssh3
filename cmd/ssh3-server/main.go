package main

import (
	"github.com/francoismichel/ssh3/cmd"
	"os"

	// authentication plugins
	_ "github.com/francoismichel/ssh3/auth/plugins/pubkey_authentication/server"
  _ "github.com/francoismichel/ssh3/auth/plugins/openpubkey/server"
)

func main() {
	os.Exit(cmd.ServerMain())
}
