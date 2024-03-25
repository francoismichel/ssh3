package main

import "os"
import "github.com/francoismichel/ssh3/cmd"

func main() {
	os.Exit(cmd.ClientMain())
}
