package main

import (
	_ "github.com/francoismichel/ssh3/auth/plugins/pubkey_authentication"
	cmd "github.com/francoismichel/ssh3/cmd"
)

func main() {
	cmd.ClientMain()
}
