package main

import (
	_ "github.com/francoismichel/ssh3/auth/plugins/pubkey_authentication"
	"github.com/francoismichel/ssh3/cmd"
	"os"
)

func main() {
	os.Exit(cmd.ClientMain())
}
