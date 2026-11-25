// Copy into the pinned, patched doctl commands package to run this fixture.
package commands

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/digitalocean/doctl/internal/oauth"
	"github.com/stretchr/testify/require"
)

type fixtureTransport func(*http.Request) (*http.Response, error)

func (f fixtureTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestIrnBruLoginAndRotate(t *testing.T) {
	cfg, _ := newOAuthTestCmdConfig(t, oauth.DefaultIssuer)
	Context = "work"
	stubOAuthLogin(t, func(_ context.Context, opts oauth.LoginOptions) (*oauth.Token, error) {
		require.Equal(t, oauth.DefaultClientID, opts.ClientID)
		return &oauth.Token{AccessToken: "fixture-access", RefreshToken: "fixture-refresh", Expiry: time.Now().Add(-time.Hour)}, nil
	})

	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	require.NoError(t, err)
	prev, previousValue := broker, priorSession
	broker = os.NewFile(uintptr(fds[0]), "worker")
	peer := os.NewFile(uintptr(fds[1]), "fixture")
	t.Cleanup(func() { broker.Close(); peer.Close(); broker = prev; priorSession = previousValue })
	type message struct {
		Op, Profile     string
		Expected, Value *string
	}
	seen := make(chan message, 3)
	go func() {
		for i := 0; i < 3; i++ {
			var size uint32
			if binary.Read(peer, binary.BigEndian, &size) != nil || size > 262144 {
				return
			}
			buf := make([]byte, size)
			if _, err := io.ReadFull(peer, buf); err != nil {
				return
			}
			var m message
			if json.Unmarshal(buf, &m) != nil {
				return
			}
			seen <- m
			reply := []byte(`{"ok":true,"value":null}`)
			if binary.Write(peer, binary.BigEndian, uint32(len(reply))) != nil {
				return
			}
			if _, err := peer.Write(reply); err != nil {
				return
			}
		}
	}()
	require.NoError(t, RunAuthLogin(cfg))
	read, save := <-seen, <-seen
	require.Equal(t, "use", read.Op)
	require.Equal(t, "work", read.Profile)
	require.Equal(t, "save", save.Op)
	require.Nil(t, save.Expected)
	require.Contains(t, *save.Value, "fixture-refresh")
	data, err := cfgFileReader()
	require.NoError(t, err)
	require.NotContains(t, string(data), "fixture-access")
	require.NotContains(t, string(data), "fixture-refresh")

	transport := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = transport })
	http.DefaultTransport = fixtureTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.String() != oauth.ServerMetadataFor(oauth.DefaultIssuer).TokenEndpoint || r.FormValue("refresh_token") != "fixture-refresh" {
			return nil, fmt.Errorf("unexpected fixture refresh request")
		}
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"access_token":"fixture-new-access","refresh_token":"fixture-new-refresh","expires_in":3600}`))}, nil
	})
	require.NoError(t, refreshExpiredOAuthToken(cfg))
	rotation := <-seen
	require.Equal(t, "work", rotation.Profile)
	require.Equal(t, "save", rotation.Op)
	require.Equal(t, save.Value, rotation.Expected)
	require.Contains(t, *rotation.Value, "fixture-new-access")
	require.Contains(t, *rotation.Value, "fixture-new-refresh")
}
