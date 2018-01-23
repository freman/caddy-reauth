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
	"strings"
	"time"

	"github.com/fellou89/caddy-cache"
	"github.com/fellou89/caddy-cache/storage"
	"github.com/fellou89/caddy-reauth/backend"
)

// Backend name
const Backend = "refresh"

// DefaultTimeout for sub requests
const DefaultTimeout = time.Minute

// Refresh backend provides authentication against a refresh token endpoint.
// If the refresh request returns a http 200 status code then the user
// is considered logged in.
type Refresh struct {
	refreshUrl         string
	cacheConfig        *cache.Config
	refreshCache       *cache.HTTPCache
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

	rf := &Refresh{
		refreshUrl:   u.String(),
		refreshCache: cache.NewHTTPCache(),
		cacheConfig: &cache.Config{
			Path:        "tmp",
			LockTimeout: time.Duration(5) * time.Minute,
		},
	}

	val, err := parseDurationOption(options, "timeout")
	if err != nil {
		return nil, err
	} else {
		rf.timeout = val
	}

	bval, err := parseBoolOption(options, "skipverify")
	if err != nil {
		return nil, err
	} else {
		rf.insecureSkipVerify = bval
	}

	bval, err = parseBoolOption(options, "follow")
	if err != nil {
		return nil, err
	} else {
		rf.followRedirects = bval
	}

	bval, err = parseBoolOption(options, "cookies")
	if err != nil {
		return nil, err
	} else {
		rf.passCookies = bval
	}

	// Cache config
	if s, found := options["cache_path"]; found {
		rf.cacheConfig.Path = s
	}

	val, err = parseDurationOption(options, "lock_timeout")
	if err != nil {
		return nil, err
	} else {
		rf.cacheConfig.LockTimeout = val
	}

	// Can't really define cache rules in one line, it would require refactor of parsing configs
	// so for now these two Config params stay out, and since cacheRules will be nil,
	// neither is used when creating HTTPCacheEntries
	//
	// DefaultMaxAge: time.Duration(5) * time.Minute,
	// CacheRules:    []cache.CacheRule{},
	//
	// rf.cacheConfig.DefaultMaxAge = parseDurationOption(options, "max_age")

	return rf, nil
}

func parseBoolOption(options map[string]string, key string) (bool, error) {
	if s, found := options[key]; found {
		if b, err := strconv.ParseBool(s); err != nil {
			return false, errors.Wrap(err, fmt.Sprintf("unable to parse %s %s", key, s))
		} else {
			return b, nil
		}
	}
	return false, nil
}

func parseDurationOption(options map[string]string, key string) (time.Duration, error) {
	if s, found := options[key]; found {
		if d, err := time.ParseDuration(s); err != nil {
			return time.Duration(0), errors.Wrap(err, fmt.Sprintf("unable to parse %s %s", key, s))
		} else {
			return d, nil
		}
	}
	return DefaultTimeout, nil
}

func fetchRefresh(client *http.Client, key string, req *http.Request, refreshRequest *http.Request, cacheConfig *cache.Config) (*cache.HTTPCacheEntry, []byte, error) {
	response := cache.NewResponse()

	if resp, err := client.Do(refreshRequest); err != nil {
		return nil, nil, err

	} else {
		if resp.StatusCode != 200 {
			return nil, nil, errors.New("Response from refresh request was not 200")
		}

		if body, err := ioutil.ReadAll(resp.Body); err != nil {
			return nil, nil, errors.Wrap(err, "Error reading response body")

		} else {
			// This creates cache files that can only live for 3 hours,
			// implementing token expiry without having to parse jwt token
			response.Header().Set("Cache-Control", "public,max-age=10800")
			response.WriteHeader(resp.StatusCode)

			return cache.NewHTTPCacheEntry(key, req, response, cacheConfig), body, nil
		}
	}
}

// Authenticate fulfils the backend interface
func (h Refresh) Authenticate(r *http.Request) (bool, error) {
	if r.Header.Get("Authorization") == "" {
		return false, errors.New("Missing Authorization Header")
	}
	jwtToken := strings.Split(r.Header.Get("Authorization"), " ")[1]

	if _, freshness := h.refreshCache.GetFreshness(r, jwtToken); freshness == 0 {
		// get value stored in cache to pass on context
		return true, nil

	} else if freshness == 2 {
		return false, nil
	}

	c := &http.Client{
		Timeout: h.timeout,
	}

	if !h.followRedirects {
		c.CheckRedirect = noRedirectsPolicy
	}

	req, err := http.NewRequest("GET", h.refreshUrl, nil)
	if err != nil {
		return false, err
	}

	if req.URL.Scheme == "https" && h.insecureSkipVerify {
		c.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	if h.passCookies {
		for _, c := range r.Cookies() {
			req.AddCookie(c)
		}
	}

	if entry, body, err := fetchRefresh(c, jwtToken, r, req, h.cacheConfig); err != nil {
		return false, err

	} else {
		if fileStore, err := storage.NewFileStorage(h.cacheConfig.Path); err != nil {
			return false, errors.Wrap(err, "Error setting up file storage for cache")

		} else {
			entry.Response.SetBody(fileStore)
		}

		// pass value to be cached on to context
		entry.Response.Write(body)
		h.refreshCache.Put(r, entry)
		return true, nil
	}

	return true, nil
}
