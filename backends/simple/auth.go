package reauth

import (
	"net/http"

	"github.com/freman/caddy-reauth/backend"
)

// Backend name
const Backend = "simple"

// Simple is the simplest backend for authentication, a name:password map
type Simple struct {
	credentials map[string]string
}

func init() {
	err := backend.Register(Backend, constructor)
	if err != nil {
		panic(err)
	}
}

func constructor(config string) (backend.Backend, error) {
	options, err := backend.ParseOptions(config)
	if err != nil {
		return nil, err
	}

	return &Simple{
		credentials: options,
	}, nil
}

// Authenticate fulfils the backend interface
func (h Simple) Authenticate(r *http.Request) (bool, error) {
	un, pw, k := r.BasicAuth()
	if !k {
		return false, nil
	}

	if p, found := h.credentials[un]; !(found && p == pw) {
		return false, nil
	}

	return true, nil
}
