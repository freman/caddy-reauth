package refresh

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/allegro/bigcache"
	"github.com/dgrijalva/jwt-go"
	"github.com/startsmartlabs/caddy-secrets"
	"gopkg.in/yaml.v2"
)

type Claims struct {
	jwt.StandardClaims
	User  string   `json:"user"`
	Email string   `json:"email"`
	Scope []string `json:"scope"`
	Type  string   `json:"type"`
	Roles []string `json:"role"`
}

var token string

func init() {
	token = "asdf"
}

func authTokenCheck(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	if strings.Contains(r.URL.String(), "return_query") {
		w.WriteHeader(200)
		w.Write([]byte("{\"message\": \"" + r.URL.String() + "\"}"))
		return

	} else if strings.Contains(r.URL.String(), "return_form") {
		bodyBytes, _ := ioutil.ReadAll(r.Body)
		w.WriteHeader(200)
		w.Write([]byte("{\"message\": \"" + string(bodyBytes) + "\"}"))
		return

	} else if strings.Contains(r.URL.String(), "return_host") {
		w.WriteHeader(200)
		w.Write([]byte("{\"message\": \"" + r.Host + "\"}"))
		return

	} else if strings.Contains(r.URL.String(), "return_cookies") {
		w.WriteHeader(200)
		w.Write([]byte("{\"message\": \"" + fmt.Sprintf("%+v", r.Cookies()) + "\"}"))
		return

	} else if strings.Contains(r.URL.String(), "return_headers") {
		w.WriteHeader(200)
		w.Write([]byte("{\"message\": \"" + fmt.Sprintf("%+v", r.Header) + "\"}"))
		return

	} else if strings.Contains(r.URL.String(), "eof") {
		w.WriteHeader(500)
		return

	} else if strings.Contains(r.URL.String(), "failure_status") {
		w.WriteHeader(500)
		w.Write([]byte("{\"error\": \"something happened\"}"))
		return

	} else if strings.Contains(r.URL.String(), "failure_equality") {
		w.WriteHeader(200)
		w.Write([]byte("{\"message\": \"something happened\"}"))
		return

	} else if strings.Contains(r.URL.String(), "failure_presence") {
		w.WriteHeader(200)
		w.Write([]byte("{\"error\": \"something happened\"}"))
		return

	}

	w.WriteHeader(200)
	w.Write([]byte("{\"jwt_token\": \"" + token + "\"}"))
	return
}

func TestAuthenticateSimple(t *testing.T) {
	fmt.Printf("\n-----TestAuthenticateSimple-----\n")

	reauth := yaml.MapSlice{}
	reauth = append(reauth, yaml.MapItem{
		Key:   "client_authorization",
		Value: true,
	})
	secrets.SecretsMap = append(secrets.SecretsMap, yaml.MapItem{
		Key:   "reauth",
		Value: reauth,
	})

	srv := httptest.NewServer(http.HandlerFunc(authTokenCheck))
	defer func() {
		srv.Close()
	}()

	cache, _ := bigcache.NewBigCache(bigcache.DefaultConfig(time.Minute))
	rf := &Refresh{
		refreshUrl:   srv.URL,
		refreshCache: cache,
		timeout:      DefaultTimeout,
	}

	t.Log("Testing no credentials")
	r, _ := http.NewRequest("GET", "https://test.example.com", nil)
	ok, err := rf.Authenticate(r)
	if err != nil {
		t.Errorf("Unexpected error `%v`", err)
	}
	if ok {
		t.Error("Authenticate should have failed")
	}

	t.Log("Testing missing 'Bearer' prefix")
	r.Header.Set("Authorization", token)
	ok, err = rf.Authenticate(r)
	if err == nil {
		t.Errorf("Expected an error, didn't get one")
	}
	if ok {
		t.Error("Authenticate should have failed")
	}

	t.Log("Testing correct credentials")
	r.Header.Set("Authorization", "Bearer "+token)
	ok, err = rf.Authenticate(r)
	if err != nil {
		t.Errorf("Unexpected error `%v`", err)
	}
	if !ok {
		t.Error("Authenticate should have succeeded")
	}

	t.Log("Testing over https with skipverify")
	rf.insecureSkipVerify = true
	ok, err = rf.Authenticate(r)
	if err != nil {
		t.Errorf("Unexpected error `%v`", err)
	}
	if !ok {
		t.Error("Authenticate should have succeeded")
	}
}

func TestAuthenticateConstructor(t *testing.T) {
	fmt.Printf("\n-----TestAuthenticateConstructor-----\n")

	reauth := yaml.MapSlice{}
	reauth = append(reauth, yaml.MapItem{
		Key:   "client_authorization",
		Value: true,
	})
	secrets.SecretsMap = append(secrets.SecretsMap, yaml.MapItem{
		Key:   "reauth",
		Value: reauth,
	})

	url := "http://google.com"
	refreshCache, _ := bigcache.NewBigCache(bigcache.DefaultConfig(time.Minute))

	tests := []struct {
		desc   string
		config string
		expect *Refresh
		err    error
	}{
		{ // 1
			`Empty configuration`,
			``,
			nil,
			errors.New(`backend configuration has to be in form 'key1=value1,key2=..', but was `),
		},
		{ // 2
			`URL only configuration`,
			`url=http://google.com`,
			&Refresh{refreshUrl: url, timeout: DefaultTimeout},
			nil,
		},
		{ // 3
			`Invalid url configuration`,
			`url=!http://google.com`,
			nil,
			errors.New(`unable to parse url !http://google.com: parse !http://google.com: first path segment in URL cannot contain colon`),
		},
		{ // 4
			`With valid arguments`,
			`url=http://google.com,timeout=5s,skipverify=true,follow=true,lifetime=1m`,
			&Refresh{refreshUrl: url, timeout: 5 * time.Second, insecureSkipVerify: true, followRedirects: true, refreshCache: refreshCache},
			nil,
		},
		{ // 5
			`With invalid timeout`,
			`url=http://google.com,timeout=5j`,
			nil,
			errors.New(`time: unknown unit j in duration 5j`),
		},
		{ // 6
			`With invalid insecure`,
			`url=http://google.com,skipverify=yesplease`,
			nil,
			errors.New(`strconv.ParseBool: parsing "yesplease": invalid syntax`),
		},
		{ // 7
			`With invalid follow`,
			`url=http://google.com,follow=yesplease`,
			nil,
			errors.New(`strconv.ParseBool: parsing "yesplease": invalid syntax`),
		},
		{ // 8
			`With valid arguments, missing url`,
			`timeout=5s,skipverify=true,follow=true`,
			nil,
			errors.New(`url is a required parameter`),
		},
		{ // 9
			`With pass cookies`,
			`url=http://google.com,cookies=true`,
			&Refresh{refreshUrl: url, timeout: DefaultTimeout, passCookies: true},
			nil,
		},
		{ // 10
			`With invalid pass cookies`,
			`url=http://google.com,cookies=yay`,
			nil,
			errors.New(`strconv.ParseBool: parsing "yay": invalid syntax`),
		},
		{ // 11
			`With invalid lifetime duration`,
			`url=http://google.com,lifetime=5j`,
			nil,
			errors.New(`time: unknown unit j in duration 5j`),
		},
		{ // 12
			`With invalid cleaninterval duration`,
			`url=http://google.com,cleaninterval=5j`,
			nil,
			errors.New(`time: unknown unit j in duration 5j`),
		},
	}

	for i, tc := range tests {
		t.Logf("%d Testing configuration (%s)", i+1, tc.desc)
		be, err := constructor(tc.config)
		if tc.err != nil {
			if err == nil {
				t.Errorf("%d Expected error, got none", i+1)
			} else if err.Error() != tc.err.Error() {
				t.Errorf("%d Expected `%+v` got `%+v`", i+1, tc.err, err)
			}
		} else if err != nil {
			t.Errorf("%d Unexpected error `%+v`", i+1, err)
		}

		if tc.expect == nil {
			if be != nil {
				t.Errorf("%d Expected nil rules, got %+v", i+1, be)
			}
		} else {
			actual, ok := be.(*Refresh)
			if !ok {
				t.Errorf("%d Expected *Refresh, got %T", i+1, be)
			} else if tc.expect.refreshUrl == actual.refreshUrl &&
				tc.expect.refreshCache == actual.refreshCache {
				t.Errorf("%d Expected \n%+v got \n%+v", i+1, tc.expect, actual)
			}
		}
	}
}

func TestRefreshRequestObject(t *testing.T) {
	fmt.Printf("\n-----TestRefreshRequestObject-----\n")

	reauth := yaml.MapSlice{}
	reauth = append(reauth, yaml.MapItem{
		Key:   "client_authorization",
		Value: true,
	})
	secrets.SecretsMap = append(secrets.SecretsMap, yaml.MapItem{
		Key:   "reauth",
		Value: reauth,
	})

	ssrv := httptest.NewTLSServer(http.HandlerFunc(authTokenCheck))
	srv := httptest.NewServer(http.HandlerFunc(authTokenCheck))
	defer func() {
		ssrv.Close()
		srv.Close()
	}()
	uri, _ := url.Parse(srv.URL)
	suri, _ := url.Parse(ssrv.URL)

	refreshCache, _ := bigcache.NewBigCache(bigcache.DefaultConfig(time.Minute))
	refresh := &Refresh{refreshUrl: uri.String(), timeout: 5 * time.Second, passCookies: true, insecureSkipVerify: true, followRedirects: true, refreshCache: refreshCache}

	c := &http.Client{Timeout: refresh.timeout}
	r, _ := http.NewRequest("GET", "http://test.example.com", nil)

	t.Log("Testing Endpoint with unhandled method")
	_, err := refresh.refreshRequestObject(c, r, Endpoint{Method: "PUT"}, map[string]string{})
	if err == nil {
		t.Errorf("Expected error got none")
	}

	t.Log("Testing Endpoint with GET method")
	_, err = refresh.refreshRequestObject(c, r, Endpoint{Method: "GET"}, map[string]string{})
	if err != nil {
		t.Errorf("Unexpected error: %s", err.Error())
	}

	t.Log("Testing Endpoint url used when set")
	refresh.refreshUrl = suri.String()
	host, err := refresh.refreshRequestObject(c, r, Endpoint{Method: "GET", Url: uri.String() + "/return_host"}, map[string]string{})
	if err != nil {
		t.Errorf("Unexpected error: %s", err.Error())
	}
	if string(host) == uri.String() {
		t.Errorf("Endpoint request did not use the uri host that was set")
	}
	refresh.refreshUrl = uri.String()

	t.Log("Testing GET Endpoint had data encoded into query string")
	refresh.refreshUrl += "/return_query"
	query, err := refresh.refreshRequestObject(c, r, Endpoint{
		Method: "GET",
		Data:   []DataObject{DataObject{Key: "one", Value: "asdf"}, DataObject{Key: "two", Value: "fdsa"}},
	}, map[string]string{})
	if err != nil {
		t.Errorf("Unexpected error: %s", err.Error())
	}
	if !strings.Contains(string(query), "one=asdf") || !strings.Contains(string(query), "two=fdsa") {
		t.Errorf("Data was not properly encoded")
	}
	refresh.refreshUrl = uri.String()

	t.Log("Testing Endpoint with POST method")
	_, err = refresh.refreshRequestObject(c, r, Endpoint{Method: "POST"}, map[string]string{})
	if err != nil {
		t.Errorf("Unexpected error: %s", err.Error())
	}

	t.Log("Testing POST Endpoint had data encoded into request form")
	refresh.refreshUrl += "/return_form"
	form, err := refresh.refreshRequestObject(c, r, Endpoint{
		Method: "POST",
		Data:   []DataObject{DataObject{Key: "one", Value: "asdf"}, DataObject{Key: "two", Value: "fdsa"}},
	}, map[string]string{})
	if err != nil {
		t.Errorf("Unexpected error: %s", err.Error())
	}
	if !strings.Contains(string(query), "one=asdf") || !strings.Contains(string(query), "two=fdsa") {
		t.Errorf("Data was not properly encoded")
	}
	refresh.refreshUrl = uri.String()

	t.Log("Testing Endpoint data replaces references with input values")
	refresh.refreshUrl += "/return_form"
	form, err = refresh.refreshRequestObject(c, r, Endpoint{
		Method: "POST",
		Data:   []DataObject{DataObject{Key: "one", Value: "{asdf}___{fdsa}___asdf___{fdsa}"}},
	}, map[string]string{"asdf": "replacement-value-for-asdf", "fdsa": "replacement-for-fdsa"})
	if err != nil {
		t.Errorf("Unexpected error: %s", err.Error())
	}
	if !strings.Contains(string(form), "one=replacement-value-for-asdf___replacement-for-fdsa___asdf___replacement-for-fdsa") {
		t.Errorf("Data reference was not replaced")
	}
	refresh.refreshUrl = uri.String()

	t.Log("Testing request client transport is modified for skipverify")
	refresh.refreshUrl = suri.String()
	refresh.refreshRequestObject(c, r, Endpoint{Method: "POST", Skipverify: true}, map[string]string{})
	if c.Transport == nil {
		t.Errorf("Client Transport was not set")
	}

	t.Log("Testing cookies are added to request if endpoint configured for it")
	r.AddCookie(&http.Cookie{Name: "one", Value: "asdf"})
	refresh.refreshUrl += "/return_cookies"
	cookies, _ := refresh.refreshRequestObject(c, r, Endpoint{Method: "POST", Cookies: true}, map[string]string{})
	if !strings.Contains(string(cookies), "[one=asdf]") {
		t.Errorf("Cookies were not added to the endpoint")
	}
	refresh.refreshUrl = uri.String()

	t.Log("Testing headers are added to request if endpoint configured for it")
	refresh.refreshUrl += "/return_headers"
	headers, _ := refresh.refreshRequestObject(c, r, Endpoint{
		Method:  "POST",
		Headers: []DataObject{DataObject{Key: "one", Value: "asdf"}, DataObject{Key: "two", Value: "fdsa"}},
	}, map[string]string{})
	if !strings.Contains(string(headers), "asdf") || !strings.Contains(string(headers), "fdsa") {
		t.Errorf("Headers were not added to the endpoint")
	}
	refresh.refreshUrl = uri.String()

	t.Log("Testing header values are replaced")
	refresh.refreshUrl += "/return_headers"
	headers, _ = refresh.refreshRequestObject(c, r, Endpoint{
		Method: "POST",
		Headers: []DataObject{
			DataObject{Key: "one", Value: "{asdf}"},
			DataObject{Key: "two", Value: "{fdsa}"},
			DataObject{Key: "three", Value: "{fdsa}"},
		}}, map[string]string{"asdf": "replacement-value-for-asdf", "fdsa": "replacement-for-fdsa"})
	if !strings.Contains(string(headers), "replacement-value-for-asdf") || !strings.Contains(string(headers), "replacement-for-fdsa") || strings.Contains(string(headers), "{fdsa}") {
		t.Errorf("Headers were not added to the endpoint")
	}
	refresh.refreshUrl = uri.String()

	t.Log("Testing client.Do error will pass error down")
	refresh.refreshUrl = "error"
	_, err = refresh.refreshRequestObject(c, r, Endpoint{Method: "POST"}, map[string]string{})
	if err == nil {
		t.Errorf("Expected an error to come back from Do")
	}
	if !strings.Contains(err.Error(), "Error on endpoint request") {
		t.Errorf("Expected error passed down should be from endpoint request")
	}
	refresh.refreshUrl = uri.String()

	t.Log("Testing failure identified in response body by status")
	refresh.refreshUrl += "/eof"
	_, err = refresh.refreshRequestObject(c, r, Endpoint{Method: "POST"}, map[string]string{})

	if !strings.Contains(err.Error(), "EOF") {
		t.Errorf("Expected EOF on an empty body")
	}
	refresh.refreshUrl = uri.String()

	t.Log("Testing failure identified in response body by status")
	refresh.refreshUrl += "/failure_status"
	failure, err := refresh.refreshRequestObject(c, r, Endpoint{
		Method: "POST",
		Failures: []Failure{Failure{
			Validation:   "status",
			Key:          "",
			Value:        "500",
			Message:      "There was a 500",
			Valuemessage: false,
		}}}, map[string]string{})

	if failure != nil {
		t.Errorf("Request failure should've returned a nil response object")
	}
	if !strings.Contains(err.Error(), "There was a 500") {
		t.Errorf("Expected Failure message to be returned")
	}
	refresh.refreshUrl = uri.String()

	t.Log("Testing failure identified in response body by body key presence")
	refresh.refreshUrl += "/failure_presence"
	failure, err = refresh.refreshRequestObject(c, r, Endpoint{
		Method: "POST",
		Failures: []Failure{Failure{
			Validation:   "presence",
			Key:          "error",
			Value:        "",
			Message:      "There was an error",
			Valuemessage: false,
		}}}, map[string]string{})

	if failure != nil {
		t.Errorf("Request failure should've returned a nil response object")
	}
	if !strings.Contains(err.Error(), "There was an error") {
		t.Errorf("Expected Failure message to be returned")
	}
	refresh.refreshUrl = uri.String()

	t.Log("Testing presence failure adds response value to error message")
	refresh.refreshUrl += "/failure_presence"
	failure, err = refresh.refreshRequestObject(c, r, Endpoint{
		Method: "POST",
		Failures: []Failure{Failure{
			Validation:   "presence",
			Key:          "error",
			Value:        "",
			Message:      "There was an error",
			Valuemessage: true,
		}}}, map[string]string{})

	if !strings.Contains(err.Error(), "something happened") {
		t.Errorf("Expected error message to have body value")
	}
	refresh.refreshUrl = uri.String()

	t.Log("Testing failure identified in response body by body key value equality")
	refresh.refreshUrl += "/failure_equality"
	failure, err = refresh.refreshRequestObject(c, r, Endpoint{
		Method: "POST",
		Failures: []Failure{Failure{
			Validation:   "equality",
			Key:          "message",
			Value:        "something happened",
			Message:      "There was an error",
			Valuemessage: false,
		}}}, map[string]string{})

	if failure != nil {
		t.Errorf("Request failure should've returned a nil response object")
	}
	if !strings.Contains(err.Error(), "There was an error") {
		t.Errorf("Expected Failure message to be returned")
	}
	refresh.refreshUrl = uri.String()

	t.Log("Testing equality failure adds value to error message")
	refresh.refreshUrl += "/failure_equality"
	failure, err = refresh.refreshRequestObject(c, r, Endpoint{
		Method: "POST",
		Failures: []Failure{Failure{
			Validation:   "equality",
			Key:          "message",
			Value:        "something happened",
			Message:      "There was an error",
			Valuemessage: true,
		}}}, map[string]string{})

	if !strings.Contains(err.Error(), "something happened") {
		t.Errorf("Expected error message to have body value")
	}
	refresh.refreshUrl = uri.String()

	t.Log("Testing response key found in response body")
	refresh.refreshUrl += "/failure_equality"
	message, err := refresh.refreshRequestObject(c, r, Endpoint{Method: "POST", Responsekey: "message"}, map[string]string{})

	if !strings.Contains(string(message), "something happened") {
		t.Errorf("Value in response object was not found")
	}
}
