package reauth

import (
	"fmt"
	"net/url"

	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

// Auth represents configuration information for the middleware
type Auth struct {
	Rules []Rule
	Next  httpserver.Handler
	Realm string
}

// Rule represents the configuration for a site
type Rule struct {
	Path               string
	ExceptedPaths      []string
	Upstream           *url.URL
	InsecureSkipVerify bool
}

func init() {
	caddy.RegisterPlugin("reauth", caddy.Plugin{
		ServerType: "http",
		Action:     Setup,
	})
}

// Setup is called by Caddy to parse the config block
func Setup(c *caddy.Controller) error {
	rules, err := parse(c)
	if err != nil {
		return err
	}

	c.OnStartup(func() error {
		fmt.Println("Reauth middleware is initiated")
		return nil
	})

	host := httpserver.GetConfig(c).Addr.Host

	httpserver.GetConfig(c).AddMiddleware(func(next httpserver.Handler) httpserver.Handler {
		return &Auth{
			Rules: rules,
			Next:  next,
			Realm: host,
		}
	})

	return nil
}

func parse(c *caddy.Controller) ([]Rule, error) {
	// This parses the following  blocks
	/*
		reauth {
			path /hello
		}
	*/
	var rules []Rule
	for c.Next() {
		args := c.RemainingArgs()
		switch len(args) {
		case 0:
			// no argument passed, check the  block

			var r = Rule{}
			for c.NextBlock() {
				switch c.Val() {
				case "path":
					if !c.NextArg() {
						// we are expecting a value
						return nil, c.ArgErr()
					}
					// return error if multiple paths in a block
					if len(r.Path) != 0 {
						return nil, c.ArgErr()
					}
					r.Path = c.Val()
					if c.NextArg() {
						// we are expecting only one value.
						return nil, c.ArgErr()
					}
				case "except":
					if !c.NextArg() {
						return nil, c.ArgErr()
					}
					r.ExceptedPaths = append(r.ExceptedPaths, c.Val())
					if c.NextArg() {
						// except only allows one path per declaration
						return nil, c.ArgErr()
					}
				case "upstream":
					if !c.NextArg() {
						// we are expecting a value
						return nil, c.ArgErr()
					}
					// return error if multiple upstreams in a block
					if r.Upstream != nil {
						return nil, c.ArgErr()
					}
					var err error
					r.Upstream, err = url.Parse(c.Val())
					if err != nil {
						return nil, c.ArgErr()
					}
					if c.NextArg() {
						// we are expecting only one value.
						return nil, c.ArgErr()
					}
				case "insecure":
					r.InsecureSkipVerify = true
				}
			}
			rules = append(rules, r)
		default:
			// we want only 0 arguments max
			return nil, c.ArgErr()
		}
	}
	// check all rules at least have a path
	for _, r := range rules {
		if r.Path == "" {
			return nil, fmt.Errorf("Each rule must have a path")
		}
	}
	return rules, nil
}
