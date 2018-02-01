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
	// "net/http/httptest"
	// "bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	// "io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/fellou89/caddy-cache"
	"github.com/fellou89/caddy-cache/storage"
	"github.com/fellou89/caddy-reauth/backend"
	. "github.com/fellou89/caddy-secrets"
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

var SecurityContext map[string]interface{}
var accessToken string

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

func (h Refresh) refreshRequestObject(c *http.Client, requestToAuth *http.Request) (*http.Request, error) {
	refreshToken := SecretsMap[0].Value.(string)
	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Add("refresh_token", refreshToken)

	refreshTokenReq, err := http.NewRequest("POST",
		"https://n0pwyybuji.execute-api.us-west-2.amazonaws.com/pre_prod/aqfer/auth/v1/access_token",
		strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}

	if refreshTokenReq.URL.Scheme == "https" && h.insecureSkipVerify {
		c.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	if h.passCookies {
		for _, c := range requestToAuth.Cookies() {
			refreshTokenReq.AddCookie(c)
		}
	}

	return refreshTokenReq, nil
}

func (h *Refresh) GetAccessToken(c *http.Client, refreshTokenReq *http.Request) error {
	refreshTokenReq.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	if refreshResp, err := c.Do(refreshTokenReq); err != nil {
		return errors.Wrap(err, "Error requesting access token")

	} else {
		if refreshBody, err := ioutil.ReadAll(refreshResp.Body); err != nil {
			return errors.Wrap(err, "Error reading response body from access token refresh")

		} else {
			var b map[string]interface{}
			json.Unmarshal(refreshBody, &b)
			if b["message"] == "Forbidden" {
				return errors.New("Auth endpoint returned Forbidden")
			}
			accessToken = b["jwt_token"].(string)

			return h.newEntry(accessToken, refreshResp.StatusCode, refreshTokenReq, refreshBody)
		}
	}
}

func (h Refresh) requestSecurityContext(c *http.Client, requestToAuth *http.Request, clientJwtToken string) (interface{}, error) {
	if securityContextReq, err := http.NewRequest("GET",
		"https://n0pwyybuji.execute-api.us-west-2.amazonaws.com/pre_prod/aqfer/auth/v1/security_context?access_token="+clientJwtToken, nil); err != nil {

		return nil, err
	} else {

		securityContextReq.Header.Add("Authorization", "Bearer "+accessToken)
		if securityContextResp, err := c.Do(securityContextReq); err != nil {
			return nil, err

		} else {
			if securityContextResp.StatusCode == 400 {
				return nil, errors.New("Invalid response from security context endpoint")
			}

			if securityContextBody, err := ioutil.ReadAll(securityContextResp.Body); err != nil {
				return nil, errors.Wrap(err, "Error reading response body from security context request")

			} else {
				var b map[string]interface{}
				json.Unmarshal(securityContextBody, &b)
				if b["message"] == "Forbidden" || b["error"] != nil {
					return nil, errors.New("Auth endpoint returned Forbidden")
				}

				if err := h.newEntry(clientJwtToken, securityContextResp.StatusCode, requestToAuth, securityContextBody); err != nil {
					return nil, err
				} else {
					return b, nil
				}
			}
		}
	}
}

func (h Refresh) newEntry(key string, statusCode int, req *http.Request, body []byte) error {
	response := cache.NewResponse()
	// This creates cache files that can only live for 3 hours,
	// implementing token expiry without having to parse jwt token
	response.Header().Set("Cache-Control", "public,max-age=10800")
	response.WriteHeader(statusCode)

	// TODO: should I be using a lock?
	// lock := handler.URLLocks.Adquire(getKey(r))

	entry := cache.NewHTTPCacheEntry(key, req, response, h.cacheConfig)

	fileStore, err := storage.NewFileStorage(h.cacheConfig.Path)
	if err != nil {
		return errors.Wrap(err, "Error setting up file storage for cache")
	}
	entry.Response.SetBody(fileStore)
	entry.Response.Write(body)
	entry.Response.Close()
	h.refreshCache.Put(req, entry)
	// lock.Unlock()

	return nil
}

// Authenticate fulfils the backend interface
func (h Refresh) Authenticate(requestToAuth *http.Request) (bool, error) {
	if requestToAuth.Header.Get("Authorization") == "" {
		// No Token, Unauthorized response
		return false, nil
	}
	authHeader := strings.Split(requestToAuth.Header.Get("Authorization"), " ")
	if len(authHeader) != 2 || authHeader[0] != "Bearer" {
		return false, errors.New("Authorization token not properly formatted")
	}
	clientJwtToken := authHeader[1]

	c := &http.Client{Timeout: h.timeout}
	if !h.followRedirects {
		c.CheckRedirect = noRedirectsPolicy
	}

	// puts together refresh request to get access token
	refreshTokenReq, err := h.refreshRequestObject(c, requestToAuth)
	if err != nil {
		return false, err
	}

	if len(accessToken) == 0 { // no access token stored, request one
		if err := h.GetAccessToken(c, refreshTokenReq); err != nil {
			return false, err
		}

	} else { // access token stored; if not fresh, get new one
		if _, freshness := h.refreshCache.GetFreshness(refreshTokenReq, accessToken); freshness == 2 {
			if err := h.GetAccessToken(c, refreshTokenReq); err != nil {
				return false, err
			}
		}
	}

	// now that an access token is stored in cache, check client token freshness and get security context
	if entry, freshness := h.refreshCache.GetFreshness(requestToAuth, clientJwtToken); freshness == 0 {
		if securityContextBody, err := entry.Response.Read(); err != nil {
			return false, errors.Wrap(err, "Error reading security context from cache")

		} else {
			// security context pulled from cache and put in play
			var b interface{}
			json.Unmarshal(securityContextBody, &b)
			SecurityContext[clientJwtToken] = b
		}

	} else if freshness == 1 { // client token is not stored
		if securityContext, err := h.requestSecurityContext(c, requestToAuth, clientJwtToken); err != nil {
			if err.Error() == "Invalid response from security context endpoint" {
				// Unauthorized from security context endpoint, TODO: check with Thiru if this is correct
				return false, nil

			} else {
				return false, err
			}
		} else {
			// storing security context for first time
			SecurityContext[clientJwtToken] = securityContext
		}

	} else if freshness == 2 {
		// client token expired, Unauthorized response
		return false, nil
	}

	return true, nil
}
