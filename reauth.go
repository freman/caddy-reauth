package reauth

import (
	"net/http"

	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

// Reauth is the main package structure containing all the goodies a good
// structure needs to live a honest life
type Reauth struct {
	rules []Rule
	next  httpserver.Handler
	realm string
}

func init() {
	caddy.RegisterPlugin("reauth", caddy.Plugin{
		ServerType: "http",
		Action:     setup,
	})
}

func setup(c *caddy.Controller) error {
	rules, err := parseConfiguration(c)
	if err != nil {
		return err
	}

	s := httpserver.GetConfig(c)

	s.AddMiddleware(func(next httpserver.Handler) httpserver.Handler {
		return &Reauth{
			rules: rules,
			next:  next,
			realm: s.Addr.Host,
		}
	})

	return nil
}

// ServeHTTP implements the handler interface for Caddy's middleware
func (h Reauth) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
RULE:
	for _, p := range h.rules {
		if !httpserver.Path(r.URL.Path).Matches(p.path) {
			continue
		}
		for _, e := range p.exceptions {
			if httpserver.Path(r.URL.Path).Matches(e) {
				continue RULE
			}
		}
		for _, b := range p.backends {
			ok, err := b.Authenticate(r)
			if err != nil {
				return http.StatusInternalServerError, err
			}
			if ok {
				return h.next.ServeHTTP(w, r)
			}
		}

		// TODO: implement a basic method of utilising multiple authenticate headers
		w.Header().Add("WWW-Authenticate", `Basic realm="`+h.realm+`"`)
		return http.StatusUnauthorized, nil
	}

	return h.next.ServeHTTP(w, r)
}
