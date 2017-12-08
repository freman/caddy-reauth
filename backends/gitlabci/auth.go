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

package gitlabci

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/fellou89/caddy-reauth/backend"
)

// Backend name
const Backend = "gitlabci"

// DefaultTimeout for sub requests
const DefaultTimeout = time.Minute

// DefaultUsername to use when talking to gitlab
const DefaultUsername = "gitlab-ci-token"

// GitlabCI backend provides authentication against gitlab paths, primarily to make
// it easier to dynamically authenticate the gitlab-ci against gitlab permitting
// testing access to otherwise private resources without storing credentials in
// gitlab or gitlab-ci.yml
//
// Authenticating against this backend should be done with the project path as
// the username and the token as the password.
//
// Example: docker login docker.example.com -u "$CI_PROJECT_PATH" -p "$CI_BUILD_TOKEN"
type GitlabCI struct {
	url                *url.URL
	timeout            time.Duration
	username           string
	insecureSkipVerify bool
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

	s, found := options["url"]
	if !found {
		return nil, errors.New("url is a required parameter")
	}

	u, err := url.Parse(s)
	if err != nil {
		return nil, fmt.Errorf("unable to parse url %s: %v", s, err)
	}

	us := &GitlabCI{
		url:      u,
		username: DefaultUsername,
		timeout:  DefaultTimeout,
	}

	if s, found := options["username"]; found {
		us.username = s
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

	return us, nil
}

func noRedirectsPolicy(req *http.Request, via []*http.Request) error {
	return errors.New("follow redirects disabled")
}

// Authenticate fulfils the backend interface
func (h GitlabCI) Authenticate(r *http.Request) (bool, error) {
	un, pw, k := r.BasicAuth()
	if !k {
		return false, nil
	}

	if !strings.HasSuffix(un, ".git") {
		un += ".git"
	}

	repo, err := h.url.Parse(un)
	if err != nil {
		return false, nil
	}

	c := &http.Client{
		Timeout:       h.timeout,
		CheckRedirect: noRedirectsPolicy,
	}

	if repo.Scheme == "https" && h.insecureSkipVerify {
		c.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	req, err := http.NewRequest("GET", repo.String(), nil)
	if err != nil {
		return false, err
	}

	req.SetBasicAuth(h.username, pw)

	resp, err := c.Do(req)
	if err != nil {
		return false, err
	}

	if resp.StatusCode != 200 {
		return false, nil
	}

	return true, nil

}
