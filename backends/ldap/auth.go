/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2018 Tamás Gulácsi
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

package ldap

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/freman/caddy-reauth/backend"

	ldp "gopkg.in/ldap.v2"
)

// Backend name
const Backend = "ldap"

// DefaultPoolSize connection pool size
const DefaultPoolSize = 10

// DefaultTimeout for sub requests
const DefaultTimeout = time.Minute

// DefaultFilter is the defauilt LDAP filter
const DefaultFilter = "(&(objectClass=user)(sAMAccountName=%s))"

// LDAP backend provides authentication against LDAP paths, for example for Microsoft AD.
//
type LDAP struct {
	url                *url.URL
	baseDN             string
	filterDN           string
	principalSuffix    string
	bindDN             string
	bindPassword       string
	tls                bool
	insecureSkipVerify bool
	timeout            time.Duration
	pool               chan ldp.Client
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

	us := &LDAP{
		timeout:         DefaultTimeout,
		principalSuffix: options["principal_suffix"],
	}

	s, found := options["url"]
	if !found {
		return nil, errors.New("url is a required parameter")
	}

	us.url, err = url.Parse(s)
	if err != nil {
		return nil, fmt.Errorf("unable to parse url %s: %v", s, err)
	}

	if us.bindDN, found = options["username"]; !found || us.bindDN == "" {
		return nil, errors.New("username is a required parameter")
	}

	if us.bindPassword, found = options["password"]; !found || us.bindPassword == "" {
		return nil, errors.New("password is a required parameter")
	}

	if us.baseDN, found = options["base"]; !found || us.baseDN == "" {
		return nil, errors.New("base_dn is a required parameter (for example: OU=Users,OU=MyCompany,DC=example,DC=com)")
	}

	if us.filterDN, found = options["filter"]; !found {
		us.filterDN = DefaultFilter
	}

	if s, found := options["insecure"]; found {
		b, err := strconv.ParseBool(s)
		if err != nil {
			return nil, fmt.Errorf("unable to parse insecure %s: %v", s, err)
		}
		us.insecureSkipVerify = b
	}

	if s, found := options["tls"]; found {
		b, err := strconv.ParseBool(s)
		if err != nil {
			return nil, fmt.Errorf("unable to parse tls %s: %v", s, err)
		}
		us.insecureSkipVerify = b
	}

	if s, found := options["timeout"]; found {
		d, err := time.ParseDuration(s)
		if err != nil {
			return nil, fmt.Errorf("unable to parse timeout %s: %v", s, err)
		}
		us.timeout = d
	}

	poolSize := DefaultPoolSize
	if s, found := options["pool_size"]; found {
		i, err := strconv.Atoi(s)
		if err != nil {
			return nil, fmt.Errorf("unable to parse pool size %s: %v", s, err)
		}
		if i > 0 {
			poolSize = i
		}
	}

	us.pool = make(chan ldp.Client, poolSize)

	return us, nil
}

// Authenticate fulfils the backend interface
func (h *LDAP) Authenticate(r *http.Request) (bool, error) {
	un, pw, k := r.BasicAuth()
	if !k {
		return false, nil
	}

	l, err := h.getConnection()
	if err != nil {
		return false, err
	}
	defer h.stashConnection(l)

	// Search for the given username
	searchRequest := ldp.NewSearchRequest(
		h.baseDN,
		ldp.ScopeWholeSubtree, ldp.NeverDerefAliases, 0, int(h.timeout/time.Second), false,
		fmt.Sprintf(h.filterDN, un+h.principalSuffix),
		[]string{"dn"},
		nil,
	)

	sr, err := l.Search(searchRequest)
	if err != nil {
		return false, fmt.Errorf("search under %q for %q: %v", h.baseDN, fmt.Sprintf(h.filterDN, un+h.principalSuffix), err)
	}

	if len(sr.Entries) == 0 {
		return false, nil // user does not exist
	}

	if len(sr.Entries) > 1 {
		return false, fmt.Errorf("too many entries returned")
	}

	userDN := sr.Entries[0].DN

	// Bind as the user to verify their password
	err = l.Bind(userDN, pw)
	if err != nil {
		if ldp.IsErrorWithCode(err, ldp.LDAPResultInvalidCredentials) {
			return false, nil
		}
		return false, fmt.Errorf("bind with %q: %v", userDN, err)
	}

	return true, nil
}

func (h *LDAP) getConnection() (ldp.Client, error) {
	var l ldp.Client
	select {
	case l = <-h.pool:
		if err := l.Bind(h.bindDN, h.bindPassword); err == nil {
			return l, nil
		}
		l.Close()
	default:
	}

	host, port, _ := net.SplitHostPort(h.url.Host)

	ldaps := port == "636" || port == "3269" || h.url.Scheme == "ldaps"
	if h.url.Scheme == "ldap" {
		ldaps = false
	}
	if port == "" || port == "0" {
		port = "389"
		if ldaps {
			port = "636"
		}
	}

	hostPort := fmt.Sprintf("%s:%s", host, port)

	var err error
	if ldaps {
		l, err = ldp.DialTLS("tcp", hostPort, &tls.Config{InsecureSkipVerify: h.insecureSkipVerify})
	} else {
		l, err = ldp.Dial("tcp", hostPort)
	}

	if err != nil {
		return nil, fmt.Errorf("connect to %q: %v", hostPort, err)
	}

	// Technically it's not impossible to run tls over ssl... just excessive
	if h.tls {
		if err = l.StartTLS(&tls.Config{InsecureSkipVerify: h.insecureSkipVerify}); err != nil {
			l.Close()
			return nil, fmt.Errorf("StartTLS: %v", err)
		}
	}

	if err := l.Bind(h.bindDN, h.bindPassword); err != nil {
		l.Close()
		return nil, fmt.Errorf("bind with %q: %v", h.bindDN, err)
	}

	return l, nil
}

func (h *LDAP) stashConnection(l ldp.Client) {
	select {
	case h.pool <- l:
		return
	default:
		l.Close()
		return
	}
}
