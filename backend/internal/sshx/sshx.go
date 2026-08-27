// Package sshx wraps golang.org/x/crypto/ssh with the connection behaviour SKM
// needs everywhere: mandatory host key verification, context-aware dialling,
// and command execution with separated output streams.
//
// There is deliberately no way to skip host key verification. A key manager
// that accepts any host key can be induced to install keys on an attacker's
// machine, or to hand its own credentials to one. ssh.InsecureIgnoreHostKey
// does not appear in this package, and CI greps to keep it that way.
package sshx

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// ErrHostKeyMismatch is returned when a target presents a host key that differs
// from its stored pin. This is either a genuine host rebuild or a
// man-in-the-middle, and SKM cannot tell the difference — so it refuses and
// makes a human decide.
var ErrHostKeyMismatch = errors.New("sshx: host key does not match the stored pin")

// DefaultTimeout bounds connection establishment.
const DefaultTimeout = 30 * time.Second

// DialOptions describes one connection attempt.
type DialOptions struct {
	Address  string
	Port     int
	Username string

	// Exactly one authentication method should be set.
	Password   string
	PrivateKey []byte

	// HostKeyPin is the expected SHA256 fingerprint ("SHA256:..."). When empty,
	// the connection trusts on first use and reports the observed key so the
	// caller can persist it.
	HostKeyPin string

	Timeout time.Duration
}

// Client is a live SSH connection.
type Client struct {
	*ssh.Client

	// HostKeyPin is the fingerprint actually presented by the server.
	HostKeyPin string
	// HostKeyIsNew reports that no pin was supplied and this one was accepted
	// on trust. The caller is expected to store it and surface the event.
	HostKeyIsNew bool
}

// Dial opens a connection, verifying the host key against the supplied pin.
//
// The context bounds the whole handshake, not just the TCP connect: x/crypto's
// own Timeout only covers the dial, so the SSH handshake is run in a goroutine
// that the context can abandon.
func Dial(ctx context.Context, opts DialOptions) (*Client, error) {
	if opts.Address == "" {
		return nil, errors.New("sshx: address is required")
	}
	if opts.Username == "" {
		return nil, errors.New("sshx: username is required")
	}
	if opts.Port == 0 {
		opts.Port = 22
	}
	if opts.Timeout == 0 {
		opts.Timeout = DefaultTimeout
	}

	auth, err := authMethods(opts)
	if err != nil {
		return nil, err
	}

	// observed captures the presented key so it can be reported back even when
	// verification fails, which is what lets the UI show old vs new.
	var observed string
	cfg := &ssh.ClientConfig{
		User:    opts.Username,
		Auth:    auth,
		Timeout: opts.Timeout,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			observed = ssh.FingerprintSHA256(key)
			if opts.HostKeyPin == "" {
				return nil // trust on first use; reported via HostKeyIsNew
			}
			if observed != opts.HostKeyPin {
				return fmt.Errorf("%w: expected %s, got %s", ErrHostKeyMismatch, opts.HostKeyPin, observed)
			}
			return nil
		},
	}

	addr := net.JoinHostPort(opts.Address, strconv.Itoa(opts.Port))

	dialer := &net.Dialer{Timeout: opts.Timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("sshx: connecting to %s: %w", addr, err)
	}

	// Guarantee the handshake cannot outlive the context.
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(opts.Timeout))
	}

	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		conn.Close()
		if errors.Is(err, ErrHostKeyMismatch) {
			return nil, err
		}
		return nil, fmt.Errorf("sshx: SSH handshake with %s: %w", addr, err)
	}

	// Clear the handshake deadline; sessions manage their own timeouts.
	_ = conn.SetDeadline(time.Time{})

	return &Client{
		Client:       ssh.NewClient(sshConn, chans, reqs),
		HostKeyPin:   observed,
		HostKeyIsNew: opts.HostKeyPin == "",
	}, nil
}

func authMethods(opts DialOptions) ([]ssh.AuthMethod, error) {
	var methods []ssh.AuthMethod

	if len(opts.PrivateKey) > 0 {
		signer, err := ssh.ParsePrivateKey(opts.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("sshx: parsing private key: %w", err)
		}
		methods = append(methods, ssh.PublicKeys(signer))
	}
	if opts.Password != "" {
		methods = append(methods, ssh.Password(opts.Password))
		// Some network devices only offer keyboard-interactive; answer every
		// prompt with the password, which is what an operator would do.
		methods = append(methods, ssh.KeyboardInteractive(
			func(name, instruction string, questions []string, echos []bool) ([]string, error) {
				answers := make([]string, len(questions))
				for i := range questions {
					answers[i] = opts.Password
				}
				return answers, nil
			}))
	}

	if len(methods) == 0 {
		return nil, errors.New("sshx: no authentication method supplied (need a password or private key)")
	}
	return methods, nil
}

// Result is the outcome of a remote command.
type Result struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

// Run executes a command and collects its output.
//
// A non-zero exit is returned in Result rather than as an error, because
// callers routinely need to distinguish "the command ran and said no" from "the
// connection broke". Only transport failures produce an error.
func (c *Client) Run(ctx context.Context, cmd string) (*Result, error) {
	session, err := c.NewSession()
	if err != nil {
		return nil, fmt.Errorf("sshx: opening session: %w", err)
	}
	defer session.Close()

	var stdout, stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr

	done := make(chan error, 1)
	go func() { done <- session.Run(cmd) }()

	select {
	case <-ctx.Done():
		// Closing the session unblocks the goroutine above.
		_ = session.Signal(ssh.SIGKILL)
		session.Close()
		return nil, fmt.Errorf("sshx: command cancelled: %w", ctx.Err())
	case err := <-done:
		res := &Result{Stdout: stdout.String(), Stderr: stderr.String()}
		if err == nil {
			return res, nil
		}
		var exitErr *ssh.ExitError
		if errors.As(err, &exitErr) {
			res.ExitCode = exitErr.ExitStatus()
			return res, nil
		}
		return res, fmt.Errorf("sshx: running command: %w", err)
	}
}

// RunInput executes a command with data supplied on stdin.
func (c *Client) RunInput(ctx context.Context, cmd string, stdin []byte) (*Result, error) {
	session, err := c.NewSession()
	if err != nil {
		return nil, fmt.Errorf("sshx: opening session: %w", err)
	}
	defer session.Close()

	var stdout, stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr
	session.Stdin = bytes.NewReader(stdin)

	done := make(chan error, 1)
	go func() { done <- session.Run(cmd) }()

	select {
	case <-ctx.Done():
		_ = session.Signal(ssh.SIGKILL)
		session.Close()
		return nil, fmt.Errorf("sshx: command cancelled: %w", ctx.Err())
	case err := <-done:
		res := &Result{Stdout: stdout.String(), Stderr: stderr.String()}
		if err == nil {
			return res, nil
		}
		var exitErr *ssh.ExitError
		if errors.As(err, &exitErr) {
			res.ExitCode = exitErr.ExitStatus()
			return res, nil
		}
		return res, fmt.Errorf("sshx: running command: %w", err)
	}
}

// RunScript feeds a sequence of lines to the remote shell in one session.
//
// It exists for network devices, where the commands are not independent. On a
// switch, "configure terminal" changes the mode that the next command runs in,
// so sending each command as its own SSH session leaves every configuration
// command executing in exec mode — where it is rejected. Devices happily read a
// command list from stdin, which is what an operator piping a change set does,
// and it is what this does too.
//
// The output of the whole batch comes back together. Callers that need one
// command's output on its own should use Run.
func (c *Client) RunScript(ctx context.Context, lines []string) (*Result, error) {
	session, err := c.NewSession()
	if err != nil {
		return nil, fmt.Errorf("sshx: opening session: %w", err)
	}
	defer session.Close()

	var stdout, stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr
	session.Stdin = strings.NewReader(strings.Join(lines, "\n") + "\n")

	done := make(chan error, 1)
	go func() {
		// A shell rather than an exec: the device's CLI is the shell, and it is
		// the thing that understands mode changes.
		if err := session.Shell(); err != nil {
			done <- err
			return
		}
		done <- session.Wait()
	}()

	select {
	case <-ctx.Done():
		_ = session.Signal(ssh.SIGKILL)
		session.Close()
		return nil, fmt.Errorf("sshx: script cancelled: %w", ctx.Err())
	case err := <-done:
		res := &Result{Stdout: stdout.String(), Stderr: stderr.String()}
		if err == nil {
			return res, nil
		}
		var exitErr *ssh.ExitError
		if errors.As(err, &exitErr) {
			res.ExitCode = exitErr.ExitStatus()
			return res, nil
		}
		return res, fmt.Errorf("sshx: running script: %w", err)
	}
}

// CheckAuth opens a connection purely to prove that credentials work, then
// closes it. This is the verification gate in a rotation: SKM only promotes a
// new key once it has independently authenticated with it.
func CheckAuth(ctx context.Context, opts DialOptions) error {
	client, err := Dial(ctx, opts)
	if err != nil {
		return err
	}
	defer client.Close()

	// Opening a session proves the connection is genuinely usable, not merely
	// that the handshake completed.
	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("sshx: authenticated but could not open a session: %w", err)
	}
	session.Close()
	return nil
}
