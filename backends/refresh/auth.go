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
	"regexp"
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

func (h Refresh) refreshRequestObject(c *http.Client, requestToAuth *http.Request, endpoint Endpoint, inputMap map[string]string) ([]byte, error) {
	data := url.Values{}
	for _, d := range endpoint.Data {
		if len(d.Input) > 0 {
			data.Set(d.Key, inputMap[d.Input])
		} else {
			data.Set(d.Key, d.Value)
		}
	}

	// In case endpoints at different urls need to be used,
	// otherwise the url set in the refresh Caddyfile entry is used
	var url string
	if len(endpoint.Url) == 0 {
		url = h.refreshUrl
	} else {
		url = endpoint.Url
	}

	var refreshTokenReq *http.Request
	var err error
	if endpoint.Method == "POST" {
		refreshTokenReq, err = http.NewRequest(endpoint.Method, url+endpoint.Path, strings.NewReader(data.Encode()))

	} else if endpoint.Method == "GET" {
		refreshTokenReq, err = http.NewRequest(endpoint.Method, url+endpoint.Path+"?"+data.Encode(), nil)
	}
	if err != nil {
		return nil, err
	}

	if endpoint.Skipverify {
		if refreshTokenReq.URL.Scheme == "https" && h.insecureSkipVerify {
			c.Transport = &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			}
		}
	}

	if endpoint.Cookies {
		if h.passCookies {
			for _, c := range requestToAuth.Cookies() {
				refreshTokenReq.AddCookie(c)
			}
		}
	}

	for _, h := range endpoint.Headers {
		if len(h.Value) > 0 {
			refreshTokenReq.Header.Add(h.Key, h.Value)

		} else {
			keyCheck := regexp.MustCompile(`(#[[:alnum:]+\-*_*]+#)`)
			keyMatch := keyCheck.FindStringSubmatch(h.Input)
			if len(keyMatch) > 0 {
				for _, m := range keyMatch[1:] {
					replace := m[1 : len(m)-1]
					replaced := strings.Replace(h.Input, m, inputMap[replace], -1)
					refreshTokenReq.Header.Add(h.Key, replaced)
				}
			}
		}
	}

	if refreshResp, err := c.Do(refreshTokenReq); err != nil {
		return nil, errors.Wrap(err, "Error requesting access token")

	} else {
		if refreshBody, err := ioutil.ReadAll(refreshResp.Body); err != nil {
			return nil, errors.Wrap(err, "Error reading response body from access token refresh")

		} else {
			var body map[string]interface{}
			json.Unmarshal(refreshBody, &body)

			for _, f := range endpoint.Failures {
				if f.Validation == "equals" {
					if body[f.Key] == f.Value {
						fmt.Println(url + endpoint.Path + ": " + f.Message)
						return nil, nil
					}
				} else if f.Validation == "presence" {
					if body[f.Key] != nil {
						fmt.Println(url + endpoint.Path + ": " + f.Message + body[f.Key].(string))
						return nil, nil
					}
				}
			}

			if len(endpoint.Responsekey) > 0 {
				if body[endpoint.Responsekey] != nil {
					return []byte(body[endpoint.Responsekey].(string)), nil
				}
			}
			return refreshBody, nil
		}
	}
}

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

func getValue(mapslice yaml.MapSlice, key string) interface{} {
	for _, s := range mapslice {
		if s.Key == key {
			return s.Value
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
	resultsMap := map[string]string{}
	resultsMap["client_token"] = authHeader[1]

	c := &http.Client{Timeout: h.timeout}
	if !h.followRedirects {
		c.CheckRedirect = noRedirectsPolicy
	}

	reauth := getObject(SecretsMap, "reauth")
	reauthEndpoints := getArray(reauth, "endpoints")
	endpointData, err := yaml.Marshal(reauthEndpoints)
	if err != nil {
		return failAuth(false, errors.New("Endpoints yaml not setup properly in secrets file"))
	}
	var endpoints []Endpoint
	yaml.Unmarshal(endpointData, &endpoints)

	// this specific structure is needed in the secrets file to have a refresh token available
	for _, e := range endpoints {
		if e.Name == "refresh" {
			for _, d := range e.Data {
				if d.Key == "refresh_token" {
					resultsMap["refresh_token"] = d.Value
				}
			}
		}
	}

	for _, endpoint := range endpoints {
		// check cache for saved response
		entry, err := h.refreshCache.Get(string(resultsMap[endpoint.Cachekey]))
		if err != nil {
			if strings.Contains(err.Error(), "not found") {
				// request data to put in cache when entry is not found
				if responseData, err := h.refreshRequestObject(c, requestToAuth, endpoint, resultsMap); err != nil {
					return failAuth(false, err)

				} else {
					if responseData == nil {
						return false, nil

					} else {
						resultsMap[endpoint.Name] = string(responseData)
						h.refreshCache.Set(resultsMap[endpoint.Cachekey], responseData)
					}
				}
			} else {
				return failAuth(false, err)
			}
		} else {
			resultsMap[endpoint.Name] = string(entry)
		}
	}

	resultkey := getValue(reauth, "resultkey").(string)
	if len(resultkey) > 0 {
		requestToAuth.ParseForm()
		requestToAuth.Form[resultkey] = []string{resultsMap[endpoints[len(endpoints)-1].Name]}
	}

	return true, nil
}

type Endpoint struct {
	Name        string
	Url         string
	Path        string
	Method      string
	Data        []DataObject
	Headers     []DataObject
	Skipverify  bool
	Cookies     bool
	Cachekey    string
	Responsekey string
	Failures    []Failure
}

type Failure struct {
	Validation string
	Key        string
	Value      string
	Message    string
}

type DataObject struct {
	Key   string
	Value string
	Input string
}

func failAuth(result bool, err error) (bool, error) {
	if err != nil {
		log.Println(err.Error())
	}
	return result, err
}
