package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/99designs/keyring"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"
)

const (
	credentialService = "mark-time"
	credentialKey     = "default"
)

type savedCredential struct {
	ServerURL string `json:"server_url"`
	Token     string `json:"token"`
}

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "hashpass":
			runHashPass()
			return
		case "auth-import":
			runAuthImport(os.Args[2:])
			return
		}
	}

	noSyncPtr := flag.Bool("sync", false, "do not sync with server")
	hashPassPtr := flag.Bool("hashpass", false, "prompt for password and print bcrypt hash")
	flag.Parse()

	if *hashPassPtr {
		runHashPass()
		return
	}

	text := strings.Join(flag.Args(), " ")

	fmt.Println("should sync", *noSyncPtr)
	fmt.Println("text", text)
}

func runHashPass() {
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
}

func runAuthImport(args []string) {
	fs := flag.NewFlagSet("auth-import", flag.ExitOnError)
	conn := fs.String("conn", "", "connection string from web UI")
	_ = fs.Parse(args)

	connectionString := strings.TrimSpace(*conn)
	if connectionString == "" {
		if fs.NArg() > 0 {
			connectionString = strings.TrimSpace(fs.Arg(0))
		}
	}

	if connectionString == "" {
		fmt.Println("usage: mark-time auth-import --conn 'marktime://auth?server=...&token=...'")
		os.Exit(1)
	}

	cred, err := parseConnectionString(connectionString)
	if err != nil {
		fmt.Printf("invalid connection string: %v\n", err)
		os.Exit(1)
	}

	if err := validateCredential(cred); err != nil {
		fmt.Printf("credential validation failed: %v\n", err)
		os.Exit(1)
	}

	if err := saveCredential(cred); err != nil {
		fmt.Printf("failed to save credential: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Saved default profile for %s\n", cred.ServerURL)
}

func parseConnectionString(s string) (savedCredential, error) {
	u, err := url.Parse(s)
	if err != nil {
		return savedCredential{}, err
	}

	if u.Scheme != "marktime" || u.Host != "auth" {
		return savedCredential{}, fmt.Errorf("scheme/host must be marktime://auth")
	}

	serverURL := strings.TrimSpace(u.Query().Get("server"))
	token := strings.TrimSpace(u.Query().Get("token"))
	if serverURL == "" || token == "" {
		return savedCredential{}, fmt.Errorf("server and token are required")
	}

	serverParsed, err := url.Parse(serverURL)
	if err != nil {
		return savedCredential{}, fmt.Errorf("invalid server url: %w", err)
	}
	if serverParsed.Scheme == "" || serverParsed.Host == "" {
		return savedCredential{}, fmt.Errorf("invalid server url")
	}

	return savedCredential{ServerURL: serverParsed.String(), Token: token}, nil
}

func saveCredential(cred savedCredential) error {
	ring, err := keyring.Open(keyring.Config{ServiceName: credentialService})
	if err != nil {
		return err
	}

	payload, err := json.Marshal(cred)
	if err != nil {
		return err
	}

	return ring.Set(keyring.Item{Key: credentialKey, Data: payload})
}

func validateCredential(cred savedCredential) error {
	client := &http.Client{Timeout: 8 * time.Second}
	req, err := http.NewRequest(http.MethodGet, strings.TrimRight(cred.ServerURL, "/")+"/auth/validate", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+cred.Token)

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		if len(body) == 0 {
			return fmt.Errorf("server returned %s", resp.Status)
		}
		return fmt.Errorf("server returned %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}

	return nil
}
