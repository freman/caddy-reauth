package reauth

// TODO: make less hax

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/freman/caddy-reauth/backend"
)

type failure interface {
	Handle(w http.ResponseWriter, r *http.Request) (int, error)
}

type httpBasicOnFailure struct {
	realm string
}

func (h *httpBasicOnFailure) Handle(w http.ResponseWriter, r *http.Request) (int, error) {
	realm := r.Host
	if h.realm != "" {
		realm = h.realm
	}
	w.Header().Add("WWW-Authenticate", `Basic realm="`+realm+`"`)
	return http.StatusUnauthorized, nil
}

type httpRedirectOnFailure struct {
	target *url.URL
	code   int
}

func (h *httpRedirectOnFailure) Handle(w http.ResponseWriter, r *http.Request) (int, error) {
	uri := r.URL
	uri.Host = ""
	uri.Scheme = ""

	// Handle redirection back to hosts that aren't the auth server.
	if h.target.Host != "" && h.target.Host != r.Host {
		uri.Host = r.Host
		uri.Scheme = "http"
		if r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
			uri.Scheme = "https"
		}
	}

	redirect := strings.Replace(h.target.String(), "{uri}", url.QueryEscape(uri.String()), -1)
	w.Header().Add("Location", redirect)
	http.Redirect(w, r, redirect, h.code)
	return h.code, nil
}

type httpStatusOnFailure struct {
	code int
}

func (h *httpStatusOnFailure) Handle(w http.ResponseWriter, r *http.Request) (int, error) {
	return h.code, nil
}

var failureHandlers = map[string]func(config string) (failure, error){
	"basicauth": func(config string) (failure, error) {
		realm := ""
		if config != "" {
			options, err := backend.ParseOptions(config)
			if err != nil {
				return nil, err
			}
			realm = options["realm"]
		}
		return &httpBasicOnFailure{realm: realm}, nil
	},
	"redirect": func(config string) (failure, error) {
		if config == "" {
			return nil, errors.New("configuration required")
		}

		options, err := backend.ParseOptions(config)
		if err != nil {
			return nil, err
		}

		s, ok := options["target"]
		if !ok {
			return nil, errors.New("target url required")
		}

		u, err := url.Parse(s)
		if err != nil {
			return nil, err
		}

		code := http.StatusFound
		if s, ok := options["code"]; ok {
			code, err = strconv.Atoi(s)
			if err != nil {
				return nil, err
			}
		}

		return &httpRedirectOnFailure{target: u, code: code}, nil
	},
	"status": func(config string) (failure, error) {
		code := http.StatusUnauthorized
		if config != "" {
			options, err := backend.ParseOptions(config)
			if err != nil {
				return nil, err
			}

			if s, ok := options["code"]; ok {
				code, err = strconv.Atoi(s)
				if err != nil {
					return nil, err
				}
			}
		}
		return &httpStatusOnFailure{code: code}, nil
	},
}
