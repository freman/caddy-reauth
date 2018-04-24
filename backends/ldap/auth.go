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
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/petrus-v/caddy-reauth/backend"

	ldp "gopkg.in/ldap.v2"
)

// Backend name
const Backend = "ldap"

// DefaultTimeout for sub requests
const DefaultTimeout = time.Minute

// DefaultPort is the default LDAP port
const DefaultPort = 389

// DefaultFilter is the defauilt LDAP filter
const DefaultFilter = "(&(objectClass=user)(sAMAccountName=%s))"

// LDAP backend provides authentication against LDAP paths, for example for Microsoft AD.
//
type LDAP struct {
	Host               string        `json:"host"`
	Port               int           `json:"port"`
	SimpleTLS          bool          `json:"simpleTls"`
	TLS                bool          `json:"tls"`
	Timeout            time.Duration `json:"timeout"`
	InsecureSkipVerify bool          `json:"insecure"`
	Base               string        `json:"base"`
	Filter             string        `json:"filter"`
	BindUsername       string        `json:"bindUsername"`
	BindPassword       string        `json:"bindPassword"`

	mu   sync.RWMutex
	conn *ldp.Conn
}

func init() {
	err := backend.Register(Backend, constructor)
	if err != nil {
		panic(err)
	}
}

var replComma = strings.NewReplacer("%2C", ",").Replace

func constructor(config string) (backend.Backend, error) {
	var us LDAP
	if err := json.Unmarshal([]byte(config), &us); err != nil {
		return nil, err
	}

	if us.Host == "" {
		return nil, errors.New("host is a required parameter")
	}
	if us.Port == 0 {
		us.Port = DefaultPort
	}
	if us.Timeout == 0 {
		us.Timeout = DefaultTimeout
	}
	if us.BindUsername == "" {
		return nil, fmt.Errorf("bindUsername is a requred parameter")
	}
	if us.BindPassword == "" {
		return nil, fmt.Errorf("bindPassword is a required paramter")
	}

	if us.Base == "" {
		return nil, fmt.Errorf("search base is required (for example: OU=Users,OU=MyCompany,DC=example,DC=com)")
	}
	if us.Filter == "" {
		us.Filter = DefaultFilter
	}

	return &us, nil
}

func noRedirectsPolicy(req *http.Request, via []*http.Request) error {
	return errors.New("follow redirects disabled")
}

// Authenticate fulfils the backend interface
func (h *LDAP) Authenticate(r *http.Request) (bool, error) {
	un, pw, k := r.BasicAuth()
	if !k {
		return false, nil
	}

	h.mu.RLock()
	l := h.conn
	h.mu.RUnlock()
	if l == nil {
		h.mu.Lock()
		if h.conn == nil {
			if err := h.connect(); err != nil {
				h.mu.Unlock()
				return false, err
			}
		}
		l = h.conn
		h.mu.Unlock()
	}
	// Search for the given username
	searchRequest := ldp.NewSearchRequest(
		h.Base,
		ldp.ScopeWholeSubtree, ldp.NeverDerefAliases, 0, int(h.Timeout/time.Second), false,
		fmt.Sprintf(h.Filter, un),
		[]string{"dn"},
		nil,
	)

	C := func() {
		h.mu.Lock()
		h.conn.Close()
		h.conn = nil
		h.mu.Unlock()
	}

	h.mu.RLock()
	sr, err := l.Search(searchRequest)
	h.mu.RUnlock()
	if err != nil {
		C()
		return false, fmt.Errorf("search under %q for %q: %v", h.Base, fmt.Sprintf(h.Filter, un), err)
	}

	if len(sr.Entries) != 1 {
		return false, fmt.Errorf("User does not exist or too many entries returned")
	}

	userdn := sr.Entries[0].DN

	// Bind as the user to verify their password
	h.mu.RLock()
	err = l.Bind(userdn, pw)
	h.mu.RUnlock()
	if err != nil {
		C()
		return false, fmt.Errorf("bind with %q: %v", userdn, err)
	}

	// Rebind as the read only user for any further queries
	if err = l.Bind(h.BindUsername, h.BindPassword); err != nil {
		C()
		return false, fmt.Errorf("bind with %q: %v", h.BindUsername, err)
	}

	return true, nil
}

func (h *LDAP) Close() error {
	h.mu.Lock()
	if h.conn != nil {
		h.conn.Close()
		h.conn = nil
	}
	h.mu.Unlock()
	return nil
}

func (h *LDAP) connect() error {
	hostport := fmt.Sprintf("%s:%d", h.Host, h.Port)
	var l *ldp.Conn
	var err error
	if h.SimpleTLS {
		l, err = ldp.DialTLS("tcp", hostport, &tls.Config{InsecureSkipVerify: h.InsecureSkipVerify})
		if err != nil {
			return fmt.Errorf("connect to %q: %v", hostport, err)
		}
	} else {
		l, err = ldp.Dial("tcp", hostport)
		if err != nil {
			return fmt.Errorf("connect to %q: %v", hostport, err)
		}
		if h.TLS {
			if err = l.StartTLS(&tls.Config{InsecureSkipVerify: h.InsecureSkipVerify}); err != nil {
				l.Close()
				return fmt.Errorf("StartTLS: %v", err)
			}
		}
	}
	// First bind with a read only user
	if err := l.Bind(h.BindUsername, h.BindPassword); err != nil {
		l.Close()
		return fmt.Errorf("bind with %q: %v", h.BindUsername, err)
	}
	h.conn = l
	return nil
}
