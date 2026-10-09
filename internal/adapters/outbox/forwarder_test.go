package outbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
	"github.com/stretchr/testify/require"
)

// TestNATSCredentials (P0.6): a bare seed authenticates as its NKey user, a
// .creds file as its JWT user; both options read the mounted file when the
// connection authenticates, so a rotated .creds file is presented on the
// next (re)connect; a broken seed is refused without echoing it.
func TestNATSCredentials(t *testing.T) {
	dir := t.TempDir()
	kp, err := nkeys.CreateUser()
	require.NoError(t, err)
	seed, err := kp.Seed()
	require.NoError(t, err)
	pub, err := kp.PublicKey()
	require.NoError(t, err)
	nonce := []byte("server-nonce")

	opt, err := natsCredentials(ForwarderConfig{})
	require.NoError(t, err)
	require.Nil(t, opt, "no credential, no option")

	seedFile := filepath.Join(dir, "user.nk")
	require.NoError(t, os.WriteFile(seedFile, append(seed, '\n'), 0o600))
	opt, err = natsCredentials(ForwarderConfig{NATSCredsFile: seedFile, NATSCredsNKey: true})
	require.NoError(t, err)
	var o nats.Options
	require.NoError(t, opt(&o))
	require.Equal(t, pub, o.Nkey)
	sig, err := o.SignatureCB(nonce)
	require.NoError(t, err)
	require.NoError(t, kp.Verify(nonce, sig))

	credsFile := filepath.Join(dir, "user.creds")
	creds := func(jwt string) []byte {
		return []byte("-----BEGIN NATS USER JWT-----\n" + jwt + "\n------END NATS USER JWT------\n\n-----BEGIN USER NKEY SEED-----\n" + string(seed) + "\n------END USER NKEY SEED------\n")
	}
	require.NoError(t, os.WriteFile(credsFile, creds("eyJhbGciOiJlZDI1NTE5LW5rZXkifQ.b25l.c2ln"), 0o600))
	opt, err = natsCredentials(ForwarderConfig{NATSCredsFile: credsFile})
	require.NoError(t, err)
	o = nats.Options{}
	require.NoError(t, opt(&o))
	jwt, err := o.UserJWT()
	require.NoError(t, err)
	require.Equal(t, "eyJhbGciOiJlZDI1NTE5LW5rZXkifQ.b25l.c2ln", jwt)
	sig, err = o.SignatureCB(nonce)
	require.NoError(t, err)
	require.NoError(t, kp.Verify(nonce, sig))
	require.NoError(t, os.WriteFile(credsFile, creds("eyJhbGciOiJlZDI1NTE5LW5rZXkifQ.dHdv.c2ln"), 0o600))
	jwt, err = o.UserJWT()
	require.NoError(t, err)
	require.Equal(t, "eyJhbGciOiJlZDI1NTE5LW5rZXkifQ.dHdv.c2ln", jwt, "the rotated file is read at the next authentication")

	broken := filepath.Join(dir, "broken.nk")
	require.NoError(t, os.WriteFile(broken, []byte("SUNOTASEEDSECRETVALUE\n"), 0o600))
	_, err = natsCredentials(ForwarderConfig{NATSCredsFile: broken, NATSCredsNKey: true})
	require.Error(t, err)
	require.False(t, strings.Contains(err.Error(), "SECRETVALUE"), "the seed is never echoed: %v", err)
}
