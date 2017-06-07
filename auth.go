package reauth

import (
	"crypto/tls"
	"fmt"
	"net/http"

	"github.com/mholt/caddy/caddyhttp/httpserver"
)

func (h Auth) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	for _, p := range h.Rules {
		if !httpserver.Path(r.URL.Path).Matches(p.Path) {
			continue
		}
		var isExceptedPath bool
		for _, e := range p.ExceptedPaths {
			if httpserver.Path(r.URL.Path).Matches(e) {
				isExceptedPath = true
			}
		}
		if isExceptedPath {
			continue
		}

		un, pw, k := r.BasicAuth()
		if !k {
			return handleUnauthorized(w, r, p, h.Realm), nil
		}

		c := &http.Client{}
		if p.Upstream.Scheme == "https" && p.InsecureSkipVerify {
			c.Transport = &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			}
		}

		req, err := http.NewRequest("GET", p.Upstream.String(), nil)
		if err != nil {
			return handleUnauthorized(w, r, p, h.Realm), nil
		}

		req.SetBasicAuth(un, pw)

		resp, err := c.Do(req)
		if err != nil {
			return handleUnauthorized(w, r, p, h.Realm), nil
		}

		if resp.StatusCode != 200 {
			return handleUnauthorized(w, r, p, h.Realm), nil
		}

		return h.Next.ServeHTTP(w, r)
	}

	return h.Next.ServeHTTP(w, r)
}

func handleUnauthorized(w http.ResponseWriter, r *http.Request, rule Rule, realm string) int {
	w.Header().Add("WWW-Authenticate", fmt.Sprintf("Bearer realm=\"%s\",error=\"invalid_token\"", realm))
	return http.StatusUnauthorized
}
