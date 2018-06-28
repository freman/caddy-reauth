package gitlabci

import (
	"crypto/x509"
	"errors"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"
)

func simplePasswordCheck(w http.ResponseWriter, r *http.Request) {
	if !strings.HasPrefix(r.URL.Path, "/group/project.git") {
		http.NotFound(w, r)
		return
	}

	u, p, k := r.BasicAuth()
	if !k {
		w.Header().Set("WWW-Authenticate", `Basic realm="test"`)
	}
	if !(u == DefaultUsername && p == "secret") {
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
}

func TestAuthenticateSimple(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(simplePasswordCheck))
	ssrv := httptest.NewTLSServer(http.HandlerFunc(simplePasswordCheck))
	defer func() {
		srv.Close()
		ssrv.Close()
	}()

	ssrv.Config.ErrorLog = log.New(ioutil.Discard, "", 0) // ಠ_ಠ

	uri, _ := url.Parse(srv.URL)
	suri, _ := url.Parse(ssrv.URL)

	us := GitlabCI{
		url:      uri,
		timeout:  DefaultTimeout,
		username: DefaultUsername,
	}

	t.Log("Testing no credentials")
	r, _ := http.NewRequest("GET", "https://test.example.com", nil)
	ok, err := us.Authenticate(r)
	if err != nil {
		t.Errorf("Unexpected error `%v`", err)
	}
	if ok {
		t.Error("Authenticate should have failed")
	}

	t.Log("Testing wrong credentials")
	r.SetBasicAuth("foo/bar", "blogs")
	ok, err = us.Authenticate(r)
	if err != nil {
		t.Errorf("Unexpected error `%v`", err)
	}
	if ok {
		t.Error("Authenticate should have failed")
	}

	t.Log("Testing correct credentials")
	r.SetBasicAuth("group/project", "secret")
	ok, err = us.Authenticate(r)
	if err != nil {
		t.Errorf("Unexpected error `%v`", err)
	}
	if !ok {
		t.Error("Authenticate should have succeeded")
	}

	t.Log("Testing over https with bad cert")
	us.url = suri
	ok, err = us.Authenticate(r)
	if err == nil {
		t.Errorf("Expected an error, didn't get one")
	} else {
		uerr, ok := err.(*url.Error)
		if !ok {
			t.Errorf("Unexpected error `%v`", err)
		} else if _, ok := uerr.Err.(x509.UnknownAuthorityError); !ok {
			t.Errorf("Unexpected error `%v`", err)
		}
	}
	if ok {
		t.Error("Authenticate should have failed")
	}

	t.Log("Testing over https with skipverify")
	us.insecureSkipVerify = true
	ok, err = us.Authenticate(r)
	if err != nil {
		t.Errorf("Unexpected error `%v`", err)
	}
	if !ok {
		t.Error("Authenticate should have succeeded")
	}

}

func TestAuthenticateConstructor(t *testing.T) {
	tests := []struct {
		desc   string
		config string
		expect *GitlabCI
		err    error
	}{
		{
			`Empty configuration`,
			``,
			nil,
			errors.New(`backend configuration has to be in form 'key1=value1,key2=..', but was `),
		}, {
			`URL only configuration`,
			`url=http://google.com`,
			&GitlabCI{url: &url.URL{Scheme: `http`, Host: `google.com`}, username: DefaultUsername, timeout: DefaultTimeout},
			nil,
		}, {
			`Invalid url configuration`,
			`url=!http://google.com`,
			nil,
			errors.New(`unable to parse url !http://google.com: parse !http://google.com: first path segment in URL cannot contain colon`),
		}, {
			`With valid arguments`,
			`url=http://google.com,timeout=5s,insecure=true,username=blahblah`,
			&GitlabCI{url: &url.URL{Scheme: `http`, Host: `google.com`}, username: `blahblah`, timeout: 5 * time.Second, insecureSkipVerify: true},
			nil,
		}, {
			`With invalid timeout`,
			`url=http://google.com,timeout=5j`,
			nil,
			errors.New(`unable to parse timeout 5j: time: unknown unit j in duration 5j`),
		}, {
			`With invalid insecure`,
			`url=http://google.com,insecure=yesplease`,
			nil,
			errors.New(`unable to parse insecure yesplease: strconv.ParseBool: parsing "yesplease": invalid syntax`),
		}, {
			`With valid arguments, missing url`,
			`timeout=5s,insecure=true,follow=true`,
			nil,
			errors.New(`url is a required parameter`),
		},
	}

	for i, tc := range tests {
		t.Logf("Testing configuration %d (%s)", i+1, tc.desc)
		be, err := constructor(tc.config)
		if tc.err != nil {
			if err == nil {
				t.Error("Expected error, got none")
			} else if err.Error() != tc.err.Error() {
				t.Errorf("Expected `%v` got `%v`", tc.err, err)
			}
		} else if err != nil {
			t.Errorf("Unexpected error `%v`", err)
		}

		if tc.expect == nil {
			if be != nil {
				t.Errorf("Expected nil rules, got %v", be)
			}
		} else {
			actual, ok := be.(*GitlabCI)
			if !ok {
				t.Errorf("Expected *GitlabCI, got %T", be)
			} else if !reflect.DeepEqual(tc.expect, actual) {
				t.Errorf("Expected %v got %v", tc.expect, actual)
			}
		}
	}
}
