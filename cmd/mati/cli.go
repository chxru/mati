package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/99designs/keyring"
	"github.com/chxru/mati/internal/db"
	"github.com/google/uuid"
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

type localEntry struct {
	LocalID    int64
	ServerID   sql.NullInt64
	ClientID   string
	Name       string
	DeviceName string
	CreatedAt  string
	NeedsPush  int
}

type syncState struct {
	LastPushedLocalID  int64
	LastPulledServerID int64
}

type syncRequest struct {
	LastPulledServerID int64           `json:"last_pulled_server_id"`
	Entries            []createPayload `json:"entries"`
}

type createPayload struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	DeviceName string `json:"device_name"`
	CreatedAt  string `json:"created_at"`
}

type syncResponse struct {
	Entries      []serverEntry `json:"entries"`
	NextServerID int64         `json:"next_server_id"`
}

type serverEntry struct {
	ServerID   int64  `json:"server_id"`
	ClientID   string `json:"client_id"`
	Name       string `json:"name"`
	DeviceName string `json:"device_name"`
	CreatedAt  string `json:"created_at"`
}

func main() {
	ctx := context.Background()

	logHandler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelWarn})
	slog.SetDefault(slog.New(logHandler))

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

	hashPassPtr := flag.Bool("hashpass", false, "prompt for password and print bcrypt hash")
	viewPtr := flag.Bool("view", false, "list local entries")
	viewShortPtr := flag.Bool("v", false, "list local entries")
	syncPtr := flag.Bool("sync", false, "sync local entries with server")
	syncShortPtr := flag.Bool("s", false, "sync local entries with server")
	os.Args = normalizeCombinedShortFlags(os.Args)
	flag.Parse()

	if *hashPassPtr {
		runHashPass()
		return
	}

	shouldView := *viewPtr || *viewShortPtr
	shouldSync := *syncPtr || *syncShortPtr

	if err := db.Init(ctx, db.TargetCLI); err != nil {
		fmt.Printf("failed to initialize cli database: %v\n", err)
		os.Exit(1)
	}
	defer func() {
		_ = db.Close()
	}()

	text := strings.Join(flag.Args(), " ")
	text = strings.TrimSpace(text)
	if text == "" && !shouldSync && !shouldView {
		fmt.Println("usage: mark-time [text] [-s|-sync] [-v|-view] | auth-import")
		os.Exit(1)
	}

	if text != "" {
		if err := createLocalEntry(ctx, text); err != nil {
			fmt.Printf("failed creating entry: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("created entry: %s\n", text)
	}

	if shouldSync {
		if err := runSync(ctx); err != nil {
			fmt.Printf("sync failed: %v\n", err)
			os.Exit(1)
		}
	}

	if shouldView {
		if err := runView(ctx); err != nil {
			fmt.Printf("view failed: %v\n", err)
			os.Exit(1)
		}
	}
}

func normalizeCombinedShortFlags(args []string) []string {
	if len(args) < 2 {
		return args
	}

	out := make([]string, 0, len(args))
	out = append(out, args[0])

	for _, arg := range args[1:] {
		if len(arg) > 2 && strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "--") {
			shortGroup := arg[1:]
			if isKnownShortFlagGroup(shortGroup) {
				for _, ch := range shortGroup {
					out = append(out, "-"+string(ch))
				}
				continue
			}
		}

		out = append(out, arg)
	}

	return out
}

func isKnownShortFlagGroup(group string) bool {
	for _, ch := range group {
		if ch != 's' && ch != 'v' {
			return false
		}
	}

	return true
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
	ring, err := openCredentialKeyring()
	if err != nil {
		return err
	}

	payload, err := json.Marshal(cred)
	if err != nil {
		return err
	}

	return ring.Set(keyring.Item{Key: credentialKey, Data: payload})
}

func loadCredential() (savedCredential, error) {
	ring, err := openCredentialKeyring()
	if err != nil {
		return savedCredential{}, err
	}

	item, err := ring.Get(credentialKey)
	if err != nil {
		return savedCredential{}, err
	}

	var cred savedCredential
	if err := json.Unmarshal(item.Data, &cred); err != nil {
		return savedCredential{}, err
	}

	return cred, nil
}

func openCredentialKeyring() (keyring.Keyring, error) {
	fileDir, err := credentialFileDir()
	if err != nil {
		return nil, fmt.Errorf("resolve file keyring directory: %w", err)
	}

	ring, err := keyring.Open(keyring.Config{
		ServiceName: credentialService,
		AllowedBackends: []keyring.BackendType{
			keyring.SecretServiceBackend,
			keyring.KWalletBackend,
			keyring.PassBackend,
			keyring.FileBackend,
		},
		FileDir:          fileDir,
		FilePasswordFunc: keyring.TerminalPrompt,
	})
	if err != nil {
		if errors.Is(err, keyring.ErrNoAvailImpl) {
			return nil, fmt.Errorf("no usable keyring backend found (tried secret-service, kwallet, pass, file). Configure one of these backends for credential storage")
		}

		return nil, err
	}

	return ring, nil
}

func credentialFileDir() (string, error) {
	if envDir := strings.TrimSpace(os.Getenv("MARK_TIME_KEYRING_FILE_DIR")); envDir != "" {
		return filepath.Clean(envDir), nil
	}

	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}

	return filepath.Join(configDir, "mark-time", "keyring"), nil
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

func createLocalEntry(ctx context.Context, name string) error {
	database := db.DB()
	if database == nil {
		return fmt.Errorf("database is not initialized")
	}

	hostname, err := os.Hostname()
	if err != nil || strings.TrimSpace(hostname) == "" {
		hostname = "unknown-device"
	}

	_, err = database.ExecContext(
		ctx,
		`insert into entries (client_id, name, device_name, created_at, needs_push) values (?, ?, ?, ?, 1)`,
		uuid.NewString(),
		name,
		hostname,
		time.Now().UTC().Format(time.RFC3339),
	)
	return err
}

func runView(ctx context.Context) error {
	entries, err := listLocalEntries(ctx)
	if err != nil {
		return err
	}

	if len(entries) == 0 {
		fmt.Println("no entries")
		return nil
	}

	for _, entry := range entries {
		displayTime := entry.CreatedAt
		if parsed, err := time.Parse(time.RFC3339, entry.CreatedAt); err == nil {
			displayTime = parsed.Local().Format("01/02 15:04")
		}

		fmt.Printf("[%s] %s (%s)\n", displayTime, entry.Name, entry.DeviceName)
	}

	return nil
}

func listLocalEntries(ctx context.Context) ([]localEntry, error) {
	database := db.DB()
	if database == nil {
		return nil, fmt.Errorf("database is not initialized")
	}

	rows, err := database.QueryContext(ctx, `
		select local_id, server_id, client_id, name, device_name, created_at, needs_push
		from entries
		order by created_at desc, coalesce(server_id, 0) desc, local_id desc
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	entries := make([]localEntry, 0)
	for rows.Next() {
		var entry localEntry
		if err := rows.Scan(&entry.LocalID, &entry.ServerID, &entry.ClientID, &entry.Name, &entry.DeviceName, &entry.CreatedAt, &entry.NeedsPush); err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return entries, nil
}

func runSync(ctx context.Context) error {
	cred, err := loadCredential()
	if err != nil {
		return fmt.Errorf("load credential: %w", err)
	}

	if err := validateCredential(cred); err != nil {
		return fmt.Errorf("credential validation failed: %w", err)
	}

	state, err := getSyncState(ctx)
	if err != nil {
		return err
	}

	unsyncedEntries, err := listUnsyncedEntries(ctx, state.LastPushedLocalID)
	if err != nil {
		return err
	}

	payload := make([]createPayload, 0, len(unsyncedEntries))
	for _, entry := range unsyncedEntries {
		payload = append(payload, createPayload{ID: entry.ClientID, Name: entry.Name, DeviceName: entry.DeviceName, CreatedAt: entry.CreatedAt})
	}

	resp, err := syncWithServer(cred, syncRequest{LastPulledServerID: state.LastPulledServerID, Entries: payload})
	if err != nil {
		return err
	}

	if err := applySyncResult(ctx, state, unsyncedEntries, resp); err != nil {
		return err
	}

	fmt.Printf("sync complete: uploaded=%d downloaded=%d\n", len(unsyncedEntries), len(resp.Entries))
	return nil
}

func getSyncState(ctx context.Context) (syncState, error) {
	database := db.DB()
	if database == nil {
		return syncState{}, fmt.Errorf("database is not initialized")
	}

	var state syncState
	err := database.QueryRowContext(ctx, `select last_pushed_local_id, last_pulled_server_id from sync_state where id = 1`).Scan(&state.LastPushedLocalID, &state.LastPulledServerID)
	if err != nil {
		return syncState{}, err
	}

	return state, nil
}

func listUnsyncedEntries(ctx context.Context, lastPushedLocalID int64) ([]localEntry, error) {
	database := db.DB()
	if database == nil {
		return nil, fmt.Errorf("database is not initialized")
	}

	rows, err := database.QueryContext(ctx, `
		select local_id, server_id, client_id, name, device_name, created_at, needs_push
		from entries
		where needs_push = 1 and local_id > ?
		order by local_id asc
	`, lastPushedLocalID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	entries := make([]localEntry, 0)
	for rows.Next() {
		var entry localEntry
		if err := rows.Scan(&entry.LocalID, &entry.ServerID, &entry.ClientID, &entry.Name, &entry.DeviceName, &entry.CreatedAt, &entry.NeedsPush); err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return entries, nil
}

func syncWithServer(cred savedCredential, reqBody syncRequest) (syncResponse, error) {
	body, err := json.Marshal(reqBody)
	if err != nil {
		return syncResponse{}, err
	}

	client := &http.Client{Timeout: 12 * time.Second}
	syncURL := strings.TrimRight(cred.ServerURL, "/") + "/sync"

	req, err := http.NewRequest(http.MethodPost, syncURL, bytes.NewReader(body))
	if err != nil {
		return syncResponse{}, err
	}
	req.Header.Set("Authorization", "Bearer "+cred.Token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return syncResponse{}, err
	}

	// Some deployments (e.g. Railway) redirect plain HTTP to HTTPS at the edge.
	// net/http follows 301/302 by switching POST to GET, which breaks POST requests.
	// Detect that specific upgrade redirect and replay the original POST body.
	if redirectsToHTTPSUpgrade(resp, syncURL) {
		redirectedURL, parseErr := resp.Location()
		_ = resp.Body.Close()
		if parseErr != nil {
			return syncResponse{}, parseErr
		}

		retryReq, reqErr := http.NewRequest(http.MethodPost, redirectedURL.String(), bytes.NewReader(body))
		if reqErr != nil {
			return syncResponse{}, reqErr
		}
		retryReq.Header.Set("Authorization", "Bearer "+cred.Token)
		retryReq.Header.Set("Content-Type", "application/json")

		resp, err = client.Do(retryReq)
		if err != nil {
			return syncResponse{}, err
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		message, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		if len(message) == 0 {
			return syncResponse{}, fmt.Errorf("server returned %s", resp.Status)
		}

		return syncResponse{}, fmt.Errorf("server returned %s: %s", resp.Status, strings.TrimSpace(string(message)))
	}

	var out syncResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return syncResponse{}, err
	}

	return out, nil
}

func redirectsToHTTPSUpgrade(resp *http.Response, originalURL string) bool {
	if resp == nil {
		return false
	}

	if resp.StatusCode != http.StatusMovedPermanently && resp.StatusCode != http.StatusFound {
		return false
	}

	loc, err := resp.Location()
	if err != nil {
		return false
	}

	original, err := url.Parse(originalURL)
	if err != nil {
		return false
	}

	return original.Scheme == "http" && strings.EqualFold(loc.Scheme, "https") && strings.EqualFold(loc.Host, original.Host) && loc.Path == original.Path
}

func applySyncResult(ctx context.Context, previous syncState, uploaded []localEntry, resp syncResponse) error {
	database := db.DB()
	if database == nil {
		return fmt.Errorf("database is not initialized")
	}

	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		return err
	}

	for _, entry := range uploaded {
		_, err = tx.ExecContext(ctx, `update entries set needs_push = 0 where local_id = ?`, entry.LocalID)
		if err != nil {
			_ = tx.Rollback()
			return err
		}
	}

	for _, entry := range resp.Entries {
		_, err = tx.ExecContext(ctx, `
			insert into entries (client_id, server_id, name, device_name, created_at, needs_push)
			values (?, ?, ?, ?, ?, 0)
			on conflict(client_id) do update set
				server_id = excluded.server_id,
				name = excluded.name,
				device_name = excluded.device_name,
				created_at = excluded.created_at,
				needs_push = 0
		`, entry.ClientID, entry.ServerID, entry.Name, entry.DeviceName, entry.CreatedAt)
		if err != nil {
			_ = tx.Rollback()
			return err
		}
	}

	newLastPushed := previous.LastPushedLocalID
	if len(uploaded) > 0 {
		sort.Slice(uploaded, func(i, j int) bool { return uploaded[i].LocalID < uploaded[j].LocalID })
		newLastPushed = uploaded[len(uploaded)-1].LocalID
	}

	_, err = tx.ExecContext(ctx, `update sync_state set last_pushed_local_id = ?, last_pulled_server_id = ? where id = 1`, newLastPushed, resp.NextServerID)
	if err != nil {
		_ = tx.Rollback()
		return err
	}

	return tx.Commit()
}
