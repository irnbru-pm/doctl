// This file is added only to the signed IrnBru build.
package commands

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"syscall"

	"github.com/digitalocean/doctl"
	"github.com/digitalocean/doctl/internal/oauth"
	"github.com/spf13/viper"
)

type managedSession struct {
	Token string           `json:"access_token"`
	OAuth *oauthTokenState `json:"oauth,omitempty"`
}

var broker = os.NewFile(3, "IrnBru broker")
var priorSession *string

func init() { syscall.CloseOnExec(3) }

func credentialRequest(op, profile string, value *string) (*string, error) {
	msg := map[string]any{"op": op, "profile": profile, "expected": priorSession, "value": value}
	data, err := json.Marshal(msg)
	if err != nil {
		return nil, err
	}
	if err = binary.Write(broker, binary.BigEndian, uint32(len(data))); err != nil {
		return nil, err
	}
	if _, err = broker.Write(data); err != nil {
		return nil, err
	}
	var size uint32
	if err = binary.Read(broker, binary.BigEndian, &size); err != nil {
		return nil, err
	}
	if size == 0 || size > 262144 {
		return nil, errors.New("invalid IrnBru response")
	}
	data = make([]byte, size)
	if _, err = io.ReadFull(broker, data); err != nil {
		return nil, err
	}
	var reply struct {
		OK    bool
		Value json.RawMessage
		Error string
	}
	if err = json.Unmarshal(data, &reply); err != nil {
		return nil, err
	}
	if !reply.OK {
		return nil, errors.New("IrnBru: " + reply.Error)
	}
	var result *string
	if err = json.Unmarshal(reply.Value, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// Viper sees the selected credential in memory. Only context names are stored on disk.
func loadManagedSession(context string) error {
	if Trace || strings.TrimSuffix(doctl.ResolvedAPIURL(), "/") != "https://api.digitalocean.com" {
		return errors.New("managed sessions require the DigitalOcean API with tracing off")
	}
	value, err := credentialRequest("use", context, nil)
	if err != nil {
		return err
	}
	priorSession = value
	var session managedSession
	if value != nil {
		if err = json.Unmarshal([]byte(*value), &session); err != nil {
			return err
		}
	}
	if context == doctl.ArgDefaultContext {
		viper.Set(doctl.ArgAccessToken, session.Token)
	} else {
		contexts := viper.GetStringMapString(authContextsKey)
		contexts[context] = session.Token
		viper.Set(authContextsKey, contexts)
	}
	viper.Set(oauthTokensConfigKey, map[string]any{})
	if session.OAuth != nil {
		state := session.OAuth
		if state.Issuer != oauth.DefaultIssuer || state.ClientID != oauth.DefaultClientID || state.TokenEndpoint != oauth.ServerMetadataFor(oauth.DefaultIssuer).TokenEndpoint {
			return errors.New("invalid DigitalOcean refresh destination")
		}
		storeOAuthTokenState(context, state)
	}
	return nil
}

func saveManagedSession(context, token string, state *oauthTokenState) error {
	data, err := json.Marshal(managedSession{Token: token, OAuth: state})
	if err != nil {
		return err
	}
	value := string(data)
	_, err = credentialRequest("save", context, &value)
	if err == nil {
		priorSession = &value
	}
	return err
}
