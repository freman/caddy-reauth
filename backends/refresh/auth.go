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

package refresh

import (
	"crypto/tls"
	"fmt"
	"github.com/pkg/errors"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/fellou89/caddy-reauth/backend"

	"github.com/nicolasazrak/caddy-cache"
	"github.com/nicolasazrak/caddy-cache/storage"
)

// Backend name
const Backend = "refresh"

// DefaultTimeout for sub requests
const DefaultTimeout = time.Minute

// Upstream backend provides authentication against an upstream http server.
// If the upstream request returns a http 200 status code then the user
// is considered logged in.
type Upstream struct {
	cacheConfig        *cache.Config
	refreshCache       *cache.HTTPCache
	refreshRequest     *http.Request
	requestKey         string
	timeout            time.Duration
	insecureSkipVerify bool
	followRedirects    bool
	passCookies        bool
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
		return nil, errors.Wrap(err, "unable to parse url "+s)
	}

	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, errors.Wrap(err, "Error forming refresh token request")
	}

	us := &Upstream{
		refreshRequest: req,
		requestKey:     GetKey(req),
		refreshCache:   cache.NewHTTPCache(),
		cacheConfig: &cache.Config{
			Path:        "tmp",
			LockTimeout: time.Duration(5) * time.Minute,
		},
		timeout: DefaultTimeout,
	}

	us.timeout = parseDurationOption(options, "timeout")
	us.insecureSkipVerify = parseBoolOption(options, "insecure")
	us.followRedirects = parseBoolOption(options, "follow")
	us.passCookies = parseBoolOption(options, "cookies")

	// Cache config
	if s, found := options["cache_path"]; found {
		us.cacheConfig.Path = s
	}

	us.cacheConfig.LockTimeout = parseDurationOption(options, "lock_timeout")

	// Can't really define cache rules in one line, it would require refactor of parsing configs
	// so for now these two Config params stay out, and since cacheRules will be nil,
	// neither is used when creating HTTPCacheEntries
	//
	// DefaultMaxAge: time.Duration(5) * time.Minute,
	// CacheRules:    []cache.CacheRule{},
	//
	// us.cacheConfig.DefaultMaxAge = parseDurationOption(options, "max_age")

	return us, nil
}

func GetKey(r *http.Request) string {
	key := fmt.Sprintf("%s %s%s", r.Method, r.Host, r.URL.Path)
	q := r.URL.Query().Encode()
	if len(q) > 0 {
		key += "?" + q
	}
	return key
}

func parseBoolOption(options map[string]string, key string) bool {
	if s, found := options[key]; found {
		if b, err := strconv.ParseBool(s); err != nil {
			fmt.Errorf("unable to parse %s %s: %v", key, s, err)
		} else {
			return b
		}
	}
	return false
}

func parseDurationOption(options map[string]string, key string) time.Duration {
	if s, found := options[key]; found {
		if d, err := time.ParseDuration(s); err != nil {
			fmt.Errorf("unable to parse %s %s: %v", key, s, err)
		} else {
			return d
		}
	}
	return time.Duration(0)
}

func (h *Upstream) fetchUpstream(c *http.Client) (*cache.HTTPCacheEntry, []byte, error) {
	response := cache.NewResponse()

	if resp, err := c.Do(h.refreshRequest); err != nil {
		return nil, nil, errors.Wrap(err, "Error executing refresh token request")

	} else {
		if resp.StatusCode != 200 {
			return nil, nil, nil
		}

		if body, err := ioutil.ReadAll(resp.Body); err != nil {
			return nil, nil, errors.Wrap(err, "Error reading response body")

		} else {

			response.Header().Set("Cache-Control", "public,max-age=7200")
			response.WriteHeader(resp.StatusCode)
			return cache.NewHTTPCacheEntry(h.requestKey, h.refreshRequest, response, h.cacheConfig), body, nil
		}
	}
}

// Authenticate fulfils the backend interface
func (h Upstream) Authenticate(r *http.Request) (bool, error) {
	c := &http.Client{
		Timeout: h.timeout,
	}

	if !h.followRedirects {
		c.CheckRedirect = noRedirectsPolicy
	}

	if h.refreshRequest.URL.Scheme == "https" && h.insecureSkipVerify {
		c.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	h.refreshRequest.Header.Add("Authorization", r.Header.Get("Authorization"))

	if h.passCookies {
		for _, c := range r.Cookies() {
			h.refreshRequest.AddCookie(c)
		}
	}

	if _, exists := h.refreshCache.Get(h.refreshRequest); exists {
		return true, nil
	}

	if entry, body, err := h.fetchUpstream(c); err != nil {
		return false, err

	} else {
		if fileStore, err := storage.NewFileStorage(h.cacheConfig.Path); err != nil {
			return false, errors.Wrap(err, "Error setting up file storage for cache")

		} else {
			entry.Response.SetBody(fileStore)
		}

		entry.Response.Write(body)
		h.refreshCache.Put(h.refreshRequest, entry)
		return true, nil
	}

	return true, nil
}
