/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2017 Shannon Wynter
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

package reauth

import (
	"net/http"

	"github.com/caddyserver/caddy"
	"github.com/caddyserver/caddy/caddyhttp/httpserver"
)

// Reauth is the main package structure containing all the goodies a good
// structure needs to live a honest life
type Reauth struct {
	rules []Rule
	next  httpserver.Handler
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
		}
	})

	return nil
}

// ServeHTTP implements the handler interface for Caddy's middleware
func (h Reauth) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
RULE:
	for _, p := range h.rules {
		protecting := false
		for _, pp := range p.path {
			if httpserver.Path(r.URL.Path).Matches(pp) {
				protecting = true
				break
			}
		}
		if !protecting {
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

		return p.onfail.Handle(w, r)
	}

	return h.next.ServeHTTP(w, r)
}
