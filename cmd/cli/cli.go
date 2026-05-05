package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"
)

func main() {
	noSyncPtr := flag.Bool("sync", false, "do not sync with server")
	hashPassPtr := flag.Bool("hashpass", false, "prompt for password and print bcrypt hash")
	flag.Parse()

	if *hashPassPtr {
		fmt.Print("Password: ")
		password, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			panic(err)
		}

		hash, err := bcrypt.GenerateFromPassword(password, bcrypt.DefaultCost)
		if err != nil {
			panic(err)
		}

		fmt.Println(string(hash))
		return
	}

	text := strings.Join(flag.Args(), " ")

	fmt.Println("should sync", *noSyncPtr)
	fmt.Println("text", text)
}
