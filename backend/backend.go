package backend

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// Backend is a reauth authentication extension
type Backend interface {
	// Authenticate checks the request against the backend.
	// If the error parameter is not nil then a communications error must have occurred
	Authenticate(r *http.Request) (bool, error)
}

type Constructor func(config string) (Backend, error)

var backends = map[string]Constructor{}

func Register(name string, f Constructor) error {
	if _, conflict := backends[name]; conflict {
		return errors.New("backend name already in use")
	}
	backends[name] = f
	return nil
}

func Lookup(name string) (Constructor, error) {
	if f, found := backends[name]; found {
		return f, nil
	}
	return nil, errors.New("unknown backend")
}

func ParseOptions(config string) (map[string]string, error) {
	opts := map[string]string{}
	pairs := strings.Split(config, ",")
	for _, p := range pairs {
		pair := strings.SplitN(p, "=", 2)
		if len(pair) != 2 {
			return nil, fmt.Errorf("backend configuration has to be in form 'key1=value1,key2=..', but was %v", p)
		}
		opts[pair[0]] = pair[1]
	}
	return opts, nil
}
