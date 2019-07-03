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
	"fmt"

	"github.com/freman/caddy-reauth/backend"
	_ "github.com/freman/caddy-reauth/backends"

	"github.com/caddyserver/caddy"
)

type Rule struct {
	path       []string
	exceptions []string
	backends   []backend.Backend
	onfail     failure
}

func parseConfiguration(c *caddy.Controller) ([]Rule, error) {
	var rules []Rule
	for c.Next() {
		args := c.RemainingArgs()
		switch len(args) {
		case 0:
			r, err := parseBlock(c)
			if err != nil {
				return nil, err
			}
			rules = append(rules, r)
		default:
			// we want only 0 arguments max
			return nil, c.ArgErr()
		}
	}
	return rules, nil
}

func parseBlock(c *caddy.Controller) (Rule, error) {
	r := Rule{backends: []backend.Backend{}}
	for c.NextBlock() {
		switch c.Val() {
		case "path":
			// Path expects just one string argument and only one iteration
			if !c.NextArg() {
				return r, c.ArgErr()
			}
			r.path = append(r.path, c.Val())
			if c.NextArg() {
				return r, c.ArgErr()
			}
		case "except":
			// Except can be specified multiple times with one string argument to
			// provide exceptions
			if !c.NextArg() {
				return r, c.ArgErr()
			}
			r.exceptions = append(r.exceptions, c.Val())
			if c.NextArg() {
				return r, c.ArgErr()
			}
		case "failure":
			if r.onfail != nil {
				return r, c.ArgErr()
			}
			if !c.NextArg() {
				return r, c.ArgErr()
			}
			name := c.Val()

			args := ""
			if c.NextArg() {
				args = c.Val()
			}

			if c.NextArg() {
				return r, c.ArgErr()
			}

			constructor, ok := failureHandlers[name]
			if !ok {
				return r, c.Errf("unknown failure handler %v: %v", name, args)
			}
			onfail, err := constructor(args)
			if err != nil {
				return r, c.Errf("%v for failure %v", err, name)
			}
			r.onfail = onfail
		default:
			// Handle backends which should all have just one argument after the plugin name
			name := c.Val()
			args := c.RemainingArgs()
			if len(args) != 1 {
				return r, fmt.Errorf("wrong number of arguments for %v: %v (%v:%v)", name, args, c.File(), c.Line())
			}

			config := args[0]

			f, err := backend.Lookup(name)
			if err != nil {
				return r, fmt.Errorf("%v for %v (%v:%v)", err, name, c.File(), c.Line())
			}

			b, err := f(config)
			if err != nil {
				return r, fmt.Errorf("%v for %v (%v:%v)", err, name, c.File(), c.Line())
			}

			r.backends = append(r.backends, b)
		}
	}

	if len(r.path) == 0 {
		return r, fmt.Errorf("at least one path is required")
	}

	if len(r.backends) == 0 {
		return r, fmt.Errorf("at least one backend required")
	}

	if r.onfail == nil {
		r.onfail = &httpBasicOnFailure{}
	}
	return r, nil
}
