package main

import (
	"flag"
	"fmt"
	"strings"
)

func main() {
	noSyncPtr := flag.Bool("sync", false, "do not sync with server")
	flag.Parse()

	text := strings.Join(flag.Args(), " ")

	fmt.Println("should sync", *noSyncPtr)
	fmt.Println("text", text)
}
