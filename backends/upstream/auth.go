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

package upstream

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"time"

	"github.com/freman/caddy-reauth/backend"
)

// Backend name
const Backend = "upstream"

// DefaultTimeout for sub requests
const DefaultTimeout = time.Minute

// Upstream backend provides authentication against an upstream http server.
// If the upstream request returns a http 200 status code then the user
// is considered logged in.
type Upstream struct {
	url                *url.URL
	timeout            time.Duration
	insecureSkipVerify bool
	followRedirects    bool
	passCookies        bool
	match              *regexp.Regexp
}

func init() {
	err := backend.Register(Backend, constructor)
	if err != nil {
		panic(err)
	}
}

func noRedirectsPolicy(req *http.Request, via []*http.Request) error {
	return errors.New("follow redirects disabled")
}

func constructor(config string) (backend.Backend, error) {
	options, err := backend.ParseOptions(config)
	if err != nil {
		return nil, err
	}

	s, found := options["url"]
	if !found {
		return nil, errors.New("url is a required parameter")
	}

	u, err := url.Parse(s)
	if err != nil {
		return nil, fmt.Errorf("unable to parse url %s: %v", s, err)
	}

	us := &Upstream{
		url:     u,
		timeout: DefaultTimeout,
	}

	if s, found := options["timeout"]; found {
		d, err := time.ParseDuration(s)
		if err != nil {
			return nil, fmt.Errorf("unable to parse timeout %s: %v", s, err)
		}
		us.timeout = d
	}

	if s, found := options["insecure"]; found {
		b, err := strconv.ParseBool(s)
		if err != nil {
			return nil, fmt.Errorf("unable to parse insecure %s: %v", s, err)
		}
		us.insecureSkipVerify = b
	}

	if s, found := options["follow"]; found {
		b, err := strconv.ParseBool(s)
		if err != nil {
			return nil, fmt.Errorf("unable to parse follow %s: %v", s, err)
		}
		us.followRedirects = b
	}

	if s, found := options["cookies"]; found {
		b, err := strconv.ParseBool(s)
		if err != nil {
			return nil, fmt.Errorf("unable to parse cookies %s: %v", s, err)
		}
		us.passCookies = b
	}

	if s, found := options["match"]; found {
		us.match, err = regexp.Compile(s)
		if err != nil {
			return nil, fmt.Errorf("unable to parse match expression %s: %v", s, err)
		}
	}

	return us, nil
}

// Authenticate fulfils the backend interface
func (h Upstream) Authenticate(r *http.Request) (bool, error) {
	un, pw, k := r.BasicAuth()
	if !(k || h.passCookies) {
		return false, nil
	}

	c := &http.Client{
		Timeout: h.timeout,
	}

	if !h.followRedirects {
		c.CheckRedirect = noRedirectsPolicy
	}

	if h.url.Scheme == "https" && h.insecureSkipVerify {
		c.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	req, err := http.NewRequest("GET", h.url.String(), nil)
	if err != nil {
		return false, err
	}

	if k {
		req.SetBasicAuth(un, pw)
	}

	if h.passCookies {
		for _, c := range r.Cookies() {
			req.AddCookie(c)
		}
	}

	resp, err := c.Do(req)
	if err != nil {
		return false, err
	}

	if resp.StatusCode != 200 {
		return false, nil
	}

	if h.match != nil && h.match.MatchString(resp.Request.URL.String()) {
		return false, nil
	}

	return true, nil

}
