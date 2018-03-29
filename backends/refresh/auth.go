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
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/allegro/bigcache"

	"github.com/fellou89/caddy-reauth/backend"

	. "github.com/startsmartlabs/caddy-secrets"
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
	refreshCache       *bigcache.BigCache
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

	life, err := parseDurationOption(options, "lifewindow")
	if err != nil {
		return nil, err
	}

	clean, err := parseDurationOption(options, "cleanwindow")
	if err != nil {
		return nil, err
	}

	cacheConfig := bigcache.DefaultConfig(life)
	cacheConfig.CleanWindow = clean
	cache, err := bigcache.NewBigCache(cacheConfig)
	if err != nil {
		return nil, err
	}

	rf := &Refresh{
		refreshUrl:   u.String(),
		refreshCache: cache,
	}

	val, err := parseDurationOption(options, "timeout")
	if err != nil {
		return nil, err
	}
	rf.timeout = val

	bval, err := parseBoolOption(options, "skipverify")
	if err != nil {
		return nil, err
	}
	rf.insecureSkipVerify = bval

	bval, err = parseBoolOption(options, "follow")
	if err != nil {
		return nil, err
	}
	rf.followRedirects = bval

	bval, err = parseBoolOption(options, "cookies")
	if err != nil {
		return nil, err
	}
	rf.passCookies = bval

	return rf, nil
}

func parseBoolOption(options map[string]string, key string) (bool, error) {
	if s, found := options[key]; found {
		return strconv.ParseBool(s)
	}
	return false, nil
}

func parseDurationOption(options map[string]string, key string) (time.Duration, error) {
	if s, found := options[key]; found {
		return time.ParseDuration(s)
	}
	return DefaultTimeout, nil
}

// func (h Refresh) refreshRequestObject(c *http.Client, requestToAuth *http.Request, refreshToken string) (*http.Request, error) {
func (h Refresh) refreshRequestObject(c *http.Client, requestToAuth *http.Request, refreshToken string) ([]byte, error) {
	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Add("refresh_token", refreshToken)

	refreshTokenReq, err := http.NewRequest("POST", h.refreshUrl+"/v1/access_token", strings.NewReader(data.Encode()))
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

	// stuff copied from GetAccessToken

	refreshTokenReq.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	if refreshResp, err := c.Do(refreshTokenReq); err != nil {
		return nil, errors.Wrap(err, "Error requesting access token")

	} else {
		if refreshBody, err := ioutil.ReadAll(refreshResp.Body); err != nil {
			return nil, errors.Wrap(err, "Error reading response body from access token refresh")

		} else {
			var b map[string]interface{}
			json.Unmarshal(refreshBody, &b)
			if b["message"] == "Forbidden" {
				// return nil, errors.New("Auth endpoint returned Forbidden")
				fmt.Println("Security Context endpoint returned Forbidden")
				return nil, nil
			}

			if b["jwt_token"] != nil {
				return []byte(b["jwt_token"].(string)), nil
			}

			// return nil, nil
			return refreshBody, nil
		}
	}

	// return refreshTokenReq, nil
}

func (h Refresh) requestSecurityContext(c *http.Client, requestToAuth *http.Request, clientJwtToken, refreshAccessToken string) ([]byte, error) {
	data := url.Values{}
	data.Set("access_token", clientJwtToken)

	securityContextReq, err := http.NewRequest("GET", h.refreshUrl+"/v1/security_context?access_token="+clientJwtToken, nil)
	// securityContextReq, err := http.NewRequest("GET", h.refreshUrl+"/v1/security_context", strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}

	securityContextReq.Header.Add("Authorization", "Bearer "+refreshAccessToken)

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

			if b["message"] == "Forbidden" {
				// return nil, errors.New("Security Context endpoint returned Forbidden")
				fmt.Println("Security Context endpoint returned Forbidden")
				return nil, nil
			}
			if b["error"] != nil {
				// return nil, errors.New(fmt.Sprintf("Security Context endpoint returned error: %v", b["error"]))
				fmt.Printf("Security Context endpoint returned error: %v\n", b["error"])
				return nil, nil
			}

			return securityContextBody, nil
		}
	}
}

// func (h *Refresh) GetAccessToken(c *http.Client, refreshTokenReq *http.Request) (string, error) {
// 	refreshTokenReq.Header.Add("Content-Type", "application/x-www-form-urlencoded")
//
// 	if refreshResp, err := c.Do(refreshTokenReq); err != nil {
// 		return "", errors.Wrap(err, "Error requesting access token")
//
// 	} else {
// 		if refreshBody, err := ioutil.ReadAll(refreshResp.Body); err != nil {
// 			return "", errors.Wrap(err, "Error reading response body from access token refresh")
//
// 		} else {
// 			var b map[string]interface{}
// 			json.Unmarshal(refreshBody, &b)
// 			if b["message"] == "Forbidden" {
// 				return "", errors.New("Auth endpoint returned Forbidden")
// 			}
// 			if b["jwt_token"] != nil {
// 				return b["jwt_token"].(string), nil
// 			}
//
// 			return "", nil
// 		}
// 	}
// }

func getObject(mapslice yaml.MapSlice, key string) yaml.MapSlice {
	for _, s := range mapslice {
		if s.Key == key {
			return s.Value.(yaml.MapSlice)
		}
	}
	return nil
}

func getArray(mapslice yaml.MapSlice, key string) []interface{} {
	for _, s := range mapslice {
		if s.Key == key {
			return s.Value.([]interface{})
		}
	}
	return nil
}

func getObjectFromArray(mapsliceArray []interface{}, key string) yaml.MapSlice {
	for _, endpoint := range mapsliceArray {
		for _, e := range endpoint.(yaml.MapSlice) {
			if e.Key == key {
				return e.Value.(yaml.MapSlice)
			}
		}
	}
	return nil
}

func getValueFromArray(mapsliceArray []interface{}, key string) interface{} {
	for _, endpoint := range mapsliceArray {
		for _, e := range endpoint.(yaml.MapSlice) {
			if e.Key == key {
				return e.Value.(interface{})
			}
		}
	}
	return nil
}

// Authenticate fulfils the backend interface
func (h Refresh) Authenticate(requestToAuth *http.Request) (bool, error) {
	if requestToAuth.Header.Get("Authorization") == "" {
		// No Token, Unauthorized response
		return failAuth(false, nil)
	}
	authHeader := strings.Split(requestToAuth.Header.Get("Authorization"), " ")
	if len(authHeader) != 2 || authHeader[0] != "Bearer" {
		return failAuth(false, errors.New("Authorization token not properly formatted"))
	}
	clientAccessToken := authHeader[1]

	c := &http.Client{Timeout: h.timeout}
	if !h.followRedirects {
		c.CheckRedirect = noRedirectsPolicy
	}

	reauth := getObject(SecretsMap, "reauth")
	reauth_endpoints := getArray(reauth, "endpoints")
	refresh := getObjectFromArray(reauth_endpoints, "refresh")
	refresh_data := getArray(refresh, "data")
	refreshToken := getValueFromArray(refresh_data, "refresh_token").(string)

	resultsMap := map[string][]byte{}

	// step 1: check cache for refresh access token
	refreshAccessEntry, err := h.refreshCache.Get(refreshToken)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			// step 1a: get refresh token access token
			if accessTokenData, err := h.refreshRequestObject(c, requestToAuth, refreshToken); err != nil {
				return failAuth(false, err)

			} else {
				// // puts together refresh request to get access token
				// refreshTokenReq, err := h.refreshRequestObject(c, requestToAuth, refreshToken)
				// if err != nil {
				// 	return failAuth(false, err)
				// }

				// // step 1a: get refresh token access token
				// refreshAccessToken, err = h.GetAccessToken(c, refreshTokenReq)
				// if err != nil {
				// 	return failAuth(false, err)
				// }
				resultsMap["refresh"] = accessTokenData
				h.refreshCache.Set(refreshToken, accessTokenData)
			}
		} else {
			return failAuth(false, err)
		}
	} else {
		resultsMap["refresh"] = refreshAccessEntry
	}

	// step 2: check cache for security context
	securityContextEntry, err := h.refreshCache.Get(clientAccessToken)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			// step 2a: get security context
			if securityContext, err := h.requestSecurityContext(c, requestToAuth, clientAccessToken, string(resultsMap["refresh"])); err != nil {
				return failAuth(false, err)

			} else {
				h.refreshCache.Set(clientAccessToken, securityContext)

				requestToAuth.ParseForm()
				requestToAuth.Form["security_context"] = []string{string(securityContext)}
			}
		} else {
			return failAuth(false, err)
		}
	} else {
		requestToAuth.ParseForm()
		requestToAuth.Form["security_context"] = []string{string(securityContextEntry)}
	}

	return true, nil
}

func failAuth(result bool, err error) (bool, error) {
	if err != nil {
		log.Println(err.Error())
	}
	return result, err
}
