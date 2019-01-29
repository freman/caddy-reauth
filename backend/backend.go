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

package backend

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
)

// Backend is a reauth authentication extension
type Backend interface {
	// Authenticate checks the request against the backend.
	// If the error parameter is not nil then a communications error must have occurred
	Authenticate(r *http.Request) (bool, error)
}

type Constructor func(config string) (Backend, error)

var backends = map[string]Constructor{}

func Register(name string, f Constructor) error {
	if _, conflict := backends[name]; conflict {
		return errors.New("backend name already in use")
	}
	backends[name] = f
	return nil
}

func Lookup(name string) (Constructor, error) {
	if f, found := backends[name]; found {
		return f, nil
	}
	return nil, errors.New("unknown backend")
}

func ParseOptions(config string) (map[string]string, error) {
	pairs := strings.Split(config, ",")

	opts := map[string]string{}

	var inset bool
	var prev string
	for _, p := range pairs {
		if inset {
			opts[prev] += "," + p
			inset = !strings.HasSuffix(p, `"`)
			continue
		}

		pair := strings.SplitN(p, "=", 2)
		if len(pair) != 2 {
			if prev == "" {
				return nil, errors.New("Unable to parse options string, missing pair")
			}
			opts[prev] += "," + pair[0]
			continue
		}
		prev = pair[0]
		inset = strings.HasPrefix(pair[1], `"`) && !strings.HasSuffix(p, `"`)
		opts[prev] = pair[1]
	}

	for n, v := range opts {
		if v, err := strconv.Unquote(v); err == nil {
			opts[n] = v
		}
	}

	return opts, nil
}
