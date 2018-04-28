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
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"

	"github.com/allegro/bigcache"
	"github.com/fellou89/caddy-reauth/backend"
	"github.com/startsmartlabs/caddy-secrets"
)

// Backend name
const Backend = "refresh"

// DefaultTimeout for sub requests
const defaultTimeout = time.Minute
const defaultLifeWindow = 3 * time.Hour
const defaultCleanWindow = time.Second
const defaultRespLimit = 1000

// Refresh backend provides authentication against a refresh token endpoint.
// If the refresh request returns a http 200 status code then the user is considered logged in.
type Refresh struct {
	refreshURL         string
	refreshCache       *bigcache.BigCache
	timeout            time.Duration
	insecureSkipVerify bool
	followRedirects    bool
	passCookies        bool
	respLimit          int64
}

var reauth yaml.MapSlice
var reauthEndpoints []interface{}
var endpoints []endpoint

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

	cache, err := setupCache(options)
	if err != nil {
		return nil, err
	}

	rf := &Refresh{
		refreshURL:   u.String(),
		refreshCache: cache,
	}
	if err = configureRefreshHandler(rf, options); err != nil {
		return nil, err
	}

	if err = initSecretValues(); err != nil {
		return nil, err
	}
	return rf, nil
}

func setupCache(options map[string]string) (*bigcache.BigCache, error) {

	life, err := parseDurationOption(options, "lifetime", defaultLifeWindow)
	if err != nil {
		return nil, err
	}

	clean, err := parseDurationOption(options, "cleaninterval", defaultCleanWindow)
	if err != nil {
		return nil, err
	}

	cacheConfig := bigcache.DefaultConfig(life)
	cacheConfig.CleanWindow = clean

	return bigcache.NewBigCache(cacheConfig)
}

func configureRefreshHandler(rf *Refresh, options map[string]string) error {
	val, err := parseDurationOption(options, "timeout", defaultTimeout)
	if err != nil {
		return err
	}
	rf.timeout = val

	bval, err := parseBoolOption(options, "skipverify")
	if err != nil {
		return err
	}
	rf.insecureSkipVerify = bval

	bval, err = parseBoolOption(options, "follow")
	if err != nil {
		return err
	}
	rf.followRedirects = bval

	bval, err = parseBoolOption(options, "cookies")
	if err != nil {
		return err
	}
	rf.passCookies = bval

	ival, err := parseIntOption(options, "limit", defaultRespLimit)
	if err != nil {
		return err
	}
	rf.respLimit = ival
	return nil
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

func initSecretValues() error {
	reauth = secrets.GetObject(secrets.SecretsMap, "reauth")
	reauthEndpoints = secrets.GetArray(reauth, "endpoints")

	endpointData, err := yaml.Marshal(reauthEndpoints)
	if err != nil {
		return errors.New("Endpoints yaml not setup properly in secrets file")
	}
	if err = yaml.Unmarshal(endpointData, &endpoints); err != nil {
		return err
	}

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

	return nil
}

func (h Refresh) refreshRequestObject(c *http.Client, requestToAuth *http.Request, e endpoint, inputMap map[string]string) ([]byte, error) {
	data := url.Values{}
	for _, d := range e.Data {
		data.Set(d.Key, replaceInputs(d.Value, inputMap))
	}
	endpointReq, err := h.prepareRequest(c, requestToAuth, e, data, inputMap)
	if err != nil {
		return nil, err
	}

	if e.Skipverify && endpointReq.URL.Scheme == "https" && h.insecureSkipVerify {
		c.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	endpointResp, body, err := h.getEndpointResponse(c, endpointReq)
	if err != nil {
		return nil, err
	}

	return endpointResult(e, endpointReq, endpointResp, body)
}

var keyCheck = regexp.MustCompile(`{([-\w]+)}`)

func replaceInputs(value string, inputMap map[string]string) string {
	keyMatch := keyCheck.FindAllStringSubmatch(value, -1)
	for _, m := range keyMatch {
		value = strings.Replace(value, m[0], inputMap[m[1]], -1)
	}
	return value
}

func (h Refresh) prepareRequest(c *http.Client, requestToAuth *http.Request, e endpoint, data url.Values, inputMap map[string]string) (*http.Request, error) {
	// In case endpoints at different urls need to be used,
	// otherwise the url set in the refresh Caddyfile entry is used
	url := h.refreshURL
	if e.URL != "" {
		url = e.URL
	}

	var req *http.Request
	var err error

	switch e.Method {
	case http.MethodPost:
		req, err = http.NewRequest(e.Method, url+e.Path, strings.NewReader(data.Encode()))
	case http.MethodGet:
		req, err = http.NewRequest(e.Method, url+e.Path+"?"+data.Encode(), nil)
	default:
		err = fmt.Errorf("Endpoint '%s' had an unhandled method '%s'", e.Name, e.Method)
	}
	if err != nil {
		return nil, err
	}

	if e.Cookies && h.passCookies {
		for _, c := range requestToAuth.Cookies() {
			req.AddCookie(c)
		}
	}

	for _, h := range e.Headers {
		req.Header.Add(h.Key, replaceInputs(h.Value, inputMap))
	}

	return req, nil
}

func (h Refresh) getEndpointResponse(c *http.Client, endpointReq *http.Request) (*http.Response, map[string]interface{}, error) {
	endpointResp, err := c.Do(endpointReq)
	if err != nil {
		return nil, nil, errors.Wrap(err, "Error on endpoint request")
	}
	defer endpointResp.Body.Close()

	var body map[string]interface{}

	dec := json.NewDecoder(io.LimitReader(endpointResp.Body, h.respLimit))
	if err = dec.Decode(&body); err != nil {
		return nil, nil, err
	}
	return endpointResp, body, nil
}

func endpointResult(e endpoint, endpointReq *http.Request, endpointResp *http.Response, body map[string]interface{}) ([]byte, error) {
	responseBody, err := json.Marshal(body)
	if err != nil {
		return nil, errors.Wrap(err, "Error marshaling object into JSON")
	}

	if err = handleEndpointFailures(e, endpointReq, endpointResp, body); err != nil {
		return responseBody, err
	}

	if len(e.Responsekey) > 0 {
		if body[e.Responsekey] != nil {
			return []byte(body[e.Responsekey].(string)), nil
		}
	}
	return responseBody, nil
}

func handleEndpointFailures(e endpoint, endpointReq *http.Request, endpointResp *http.Response, body map[string]interface{}) error {
	for _, f := range e.Failures {
		failureString := endpointReq.URL.String() + e.Path + ": " + f.Message
		failed := false

		if strings.EqualFold(f.Validation, "status") {
			failed = strings.Contains(endpointResp.Status, f.Value)

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
			return errors.New(failureString)
		}
	}
	return nil
}

func (h Refresh) authProcessingSetup(requestToAuth *http.Request) (map[string]string, *http.Client, error) {
	resultsMap := map[string]string{}

	if clientAuth, isa := secrets.GetValue(reauth, "client_authorization").(int); isa && clientAuth > 0 {
		if requestToAuth.Header.Get("Authorization") == "" {
			if clientAuth == 2 {
				return nil, nil, errors.New("Missing bearer token from Authorization Header")
			}
			return nil, nil, nil
		}
		authHeader := strings.Split(requestToAuth.Header.Get("Authorization"), " ")
		if len(authHeader) != 2 || authHeader[0] != "Bearer" {
			return nil, nil, errors.New("Authorization token not properly formatted")
		}
		resultsMap["client_token"] = authHeader[1]
	}

	c := &http.Client{Timeout: h.timeout}
	if !h.followRedirects {
		c.CheckRedirect = noRedirectsPolicy
	}

	resultsMap["refresh_token"] = refreshToken

	return resultsMap, c, nil
}

// Authenticate fulfils the backend interface
func (h Refresh) Authenticate(requestToAuth *http.Request) (bool, error) {
	resultsMap, c, err := h.authProcessingSetup(requestToAuth)
	if err != nil || resultsMap == nil {
		return failAuth(err)
	}

	for _, e := range endpoints {
		// check cache for saved response
		entry, err := h.refreshCache.Get(string(resultsMap[e.Cachekey]))
		if err != nil {
			if _, isa := err.(*bigcache.EntryNotFoundError); isa {
				// request data to put in cache when entry is not found
				responseData, err := h.refreshRequestObject(c, requestToAuth, e, resultsMap)
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
				resultsMap[e.Name] = string(responseData)
				err = h.refreshCache.Set(resultsMap[e.Cachekey], responseData)
				if err != nil {
					return failAuth(err)
				}
			} else {
				// error different than not found cache key cause server error (500)
				return failAuth(err)
			}
		} else {
			// value found in cache sets it directly to resultsMap
			resultsMap[e.Name] = string(entry)
		}
	}

	if len(resultKey) > 0 {
		if err = requestToAuth.ParseForm(); err != nil {
			return failAuth(err)
		}
		requestToAuth.Form[resultKey] = []string{resultsMap[endpoints[len(endpoints)-1].Name]}
	}

	return true, nil
}

type endpoint struct {
	Name        string
	URL         string
	Path        string
	Method      string
	Data        []dataObject
	Headers     []dataObject
	Skipverify  bool
	Cookies     bool
	Cachekey    string
	Responsekey string
	Failures    []failure
}

type failure struct {
	Validation   string
	Key          string
	Value        string
	Message      string
	Valuemessage bool
}

type dataObject struct {
	Key   string
	Value string
}

func failAuth(err error) (bool, error) {
	if err != nil {
		fmt.Println(err.Error())
	}
	return false, err
}
