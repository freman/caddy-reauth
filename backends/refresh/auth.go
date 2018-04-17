/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2017 Alfredo Uribe
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
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/allegro/bigcache"
	"github.com/fellou89/caddy-reauth/backend"
	"github.com/startsmartlabs/caddy-secrets"
)

// Backend name
const Backend = "refresh"

// DefaultTimeout for sub requests
const DefaultTimeout = time.Minute
const DefaultLifeWindow = 3 * time.Hour
const DefaultCleanWindow = time.Second
const DefaultRespLimit = 1000

// Refresh backend provides authentication against a refresh token endpoint.
// If the refresh request returns a http 200 status code then the user is considered logged in.
type Refresh struct {
	refreshUrl         string
	refreshCache       *bigcache.BigCache
	timeout            time.Duration
	insecureSkipVerify bool
	followRedirects    bool
	passCookies        bool
	respLimit          int64
}

var reauth yaml.MapSlice
var reauthEndpoints []interface{}
var endpoints []Endpoint

func init() {
	err := backend.Register(Backend, constructor)
	if err != nil {
		panic(err)
	}
}

func noRedirectsPolicy(req *http.Request, via []*http.Request) error {
	return errors.New("follow redirects disabled")
}

var refreshToken string
var resultKey string

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

	life, err := parseDurationOption(options, "lifetime", DefaultLifeWindow)
	if err != nil {
		return nil, err
	}

	clean, err := parseDurationOption(options, "cleaninterval", DefaultCleanWindow)
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

	val, err := parseDurationOption(options, "timeout", DefaultTimeout)
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

	ival, err := parseIntOption(options, "limit", DefaultRespLimit)
	if err != nil {
		return nil, err
	}
	rf.respLimit = ival

	reauth = secrets.GetObject(secrets.SecretsMap, "reauth")
	reauthEndpoints = secrets.GetArray(reauth, "endpoints")

	endpointData, err := yaml.Marshal(reauthEndpoints)
	if err != nil {
		return nil, errors.New("Endpoints yaml not setup properly in secrets file")
	}
	yaml.Unmarshal(endpointData, &endpoints)

	// this specific structure is needed in the secrets file to have a refresh token available
	for _, e := range endpoints {
		if e.Name == "refresh" {
			for _, d := range e.Data {
				if d.Key == "refresh_token" {
					refreshToken = d.Value
				}
			}
		}
	}

	if secrets.FindKey(reauth, "resultkey") {
		resultKey = secrets.GetValue(reauth, "resultkey").(string)
	}

	return rf, nil
}

func parseIntOption(options map[string]string, key string, def int64) (int64, error) {
	if s, found := options[key]; found {
		return strconv.ParseInt(s, 10, 64)
	}
	return def, nil
}

func parseBoolOption(options map[string]string, key string) (bool, error) {
	if s, found := options[key]; found {
		return strconv.ParseBool(s)
	}
	return false, nil
}

func parseDurationOption(options map[string]string, key string, def time.Duration) (time.Duration, error) {
	if s, found := options[key]; found {
		return time.ParseDuration(s)
	}
	return def, nil
}

func (h Refresh) refreshRequestObject(c *http.Client, requestToAuth *http.Request, endpoint Endpoint, inputMap map[string]string) ([]byte, error) {
	data := url.Values{}
	for _, d := range endpoint.Data {
		data.Set(d.Key, replaceInputs(d.Value, inputMap))
	}

	// In case endpoints at different urls need to be used,
	// otherwise the url set in the refresh Caddyfile entry is used
	url := h.refreshUrl
	if endpoint.Url != "" {
		url = endpoint.Url
	}

	var refreshTokenReq *http.Request
	var err error

	switch endpoint.Method {
	case http.MethodPost:
		refreshTokenReq, err = http.NewRequest(endpoint.Method, url+endpoint.Path, strings.NewReader(data.Encode()))
	case http.MethodGet:
		refreshTokenReq, err = http.NewRequest(endpoint.Method, url+endpoint.Path+"?"+data.Encode(), nil)
	default:
		err = fmt.Errorf("Endpoint '%s' had an unhandled method '%s'", endpoint.Name, endpoint.Method)
	}
	if err != nil {
		return nil, err
	}

	if endpoint.Skipverify && refreshTokenReq.URL.Scheme == "https" && h.insecureSkipVerify {
		c.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	if endpoint.Cookies && h.passCookies {
		for _, c := range requestToAuth.Cookies() {
			refreshTokenReq.AddCookie(c)
		}
	}

	for _, h := range endpoint.Headers {
		refreshTokenReq.Header.Add(h.Key, replaceInputs(h.Value, inputMap))
	}

	refreshResp, err := c.Do(refreshTokenReq)
	if err != nil {
		return nil, errors.Wrap(err, "Error on endpoint request")
	}
	defer refreshResp.Body.Close()
	var body map[string]interface{}

	dec := json.NewDecoder(io.LimitReader(refreshResp.Body, h.respLimit))
	if err := dec.Decode(&body); err != nil {
		return nil, err
	}

	responseBody, err := json.Marshal(body)
	if err != nil {
		return nil, errors.Wrap(err, "Error marshaling object into JSON")
	}

	for _, f := range endpoint.Failures {
		failureString := url + endpoint.Path + ": " + f.Message
		failed := false

		if strings.EqualFold(f.Validation, "status") {
			failed = strings.Contains(refreshResp.Status, f.Value)

		} else {
			if f.Valuemessage && body[f.Key] != nil {
				failureString += body[f.Key].(string)
			}

			if strings.EqualFold(f.Validation, "equality") {
				failed = (body[f.Key] == f.Value)

			} else if strings.EqualFold(f.Validation, "presence") {
				failed = (body[f.Key] != nil)
			}
		}

		if failed {
			return responseBody, errors.New(failureString)
		}
	}

	if len(endpoint.Responsekey) > 0 {
		if body[endpoint.Responsekey] != nil {
			return []byte(body[endpoint.Responsekey].(string)), nil
		}
	}
	return responseBody, nil
}

var keyCheck = regexp.MustCompile(`{([-\w]+)}`)

func replaceInputs(value string, inputMap map[string]string) string {
	keyMatch := keyCheck.FindAllStringSubmatch(value, -1)
	for _, m := range keyMatch {
		value = strings.Replace(value, m[0], inputMap[m[1]], -1)
	}
	return value
}

// Authenticate fulfils the backend interface
func (h Refresh) Authenticate(requestToAuth *http.Request) (bool, error) {
	resultsMap := map[string]string{}

	if client_auth, isa := secrets.GetValue(reauth, "client_authorization").(bool); isa && client_auth {
		if requestToAuth.Header.Get("Authorization") == "" {
			return failAuth(nil)
		}
		authHeader := strings.Split(requestToAuth.Header.Get("Authorization"), " ")
		if len(authHeader) != 2 || authHeader[0] != "Bearer" {
			return failAuth(errors.New("Authorization token not properly formatted"))
		}
		resultsMap["client_token"] = authHeader[1]
	}

	c := &http.Client{Timeout: h.timeout}
	if !h.followRedirects {
		c.CheckRedirect = noRedirectsPolicy
	}

	resultsMap["refresh_token"] = refreshToken

	for _, endpoint := range endpoints {
		// check cache for saved response
		entry, err := h.refreshCache.Get(string(resultsMap[endpoint.Cachekey]))
		if err != nil {
			if _, isa := err.(*bigcache.EntryNotFoundError); isa {
				// request data to put in cache when entry is not found
				responseData, err := h.refreshRequestObject(c, requestToAuth, endpoint, resultsMap)
				if err != nil {
					if responseData == nil {
						// error and empty response signal an auth fail due to server error (500)
						return failAuth(err)

					}
					// error and response signal an auth fail due to unauthorized response from server
					// Authorize returns false and no error, so that caddyfile configured response is given
					failAuth(err)
					return false, nil

				}
				// nil error and response signal successful authentication
				resultsMap[endpoint.Name] = string(responseData)
				h.refreshCache.Set(resultsMap[endpoint.Cachekey], responseData)
			} else {
				// error different than not found cache key cause server error (500)
				return failAuth(err)
			}
		} else {
			// value found in cache sets it directly to resultsMap
			resultsMap[endpoint.Name] = string(entry)
		}
	}

	if len(resultKey) > 0 {
		requestToAuth.ParseForm()
		requestToAuth.Form[resultKey] = []string{resultsMap[endpoints[len(endpoints)-1].Name]}
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
	Validation   string
	Key          string
	Value        string
	Message      string
	Valuemessage bool
}

type DataObject struct {
	Key   string
	Value string
}

func failAuth(err error) (bool, error) {
	if err != nil {
		fmt.Println(err.Error())
	}
	return false, err
}
