package secrets

import (
	"github.com/caddyserver/caddy"
	"github.com/caddyserver/caddy/caddyhttp/httpserver"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/hashicorp/go-getter"
)

func init() {
	caddy.RegisterPlugin("secrets", caddy.Plugin{
		ServerType: "http",
		Action:     Setup,
	})
}

type SecretsHandler struct {
	Next httpserver.Handler
}

var SecretsMap yaml.MapSlice

func GetObject(mapslice yaml.MapSlice, key string) yaml.MapSlice {
	for _, s := range mapslice {
		if s.Key == key {
			return s.Value.(yaml.MapSlice)
		}
	}
	return nil
}

func GetArray(mapslice yaml.MapSlice, key string) []interface{} {
	for _, s := range mapslice {
		if s.Key == key {
			return s.Value.([]interface{})
		}
	}
	return nil
}

func GetValue(mapslice yaml.MapSlice, key string) interface{} {
	for _, s := range mapslice {
		if s.Key == key {
			return s.Value
		}
	}
	return nil
}

func FindKey(mapslice yaml.MapSlice, key string) bool {
	for _, s := range mapslice {
		if s.Key == key {
			return true
		}
	}
	return false
}

func Setup(c *caddy.Controller) error {
	if c.Next() {

		c.Next()
		fileName := c.Val()

		pwd, err := os.Getwd()
		if err != nil {
			return err
		}

		client := &getter.Client{
			Src:     fileName,
			Dst:     ".secrets_file.yml",
			Dir:     false,
			Pwd:     pwd,
			Getters: getter.Getters,
		}

		if err := client.Get(); err != nil {
			return errors.Wrap(err, "Error downloading")
		}
		if err := readFile(".secrets_file.yml"); err != nil {
			return err
		}

		cfg := httpserver.GetConfig(c)
		mid := func(next httpserver.Handler) httpserver.Handler {
			return SecretsHandler{
				Next: next,
			}
		}
		cfg.AddMiddleware(mid)

		if len(c.RemainingArgs()) > 0 {
			return errors.New("Secrets middleware received more arguments than expected")
		}
	}
	return nil
}

func readFile(fileName string) error {
	m := yaml.MapSlice{}
	if content, err := ioutil.ReadFile(fileName); err != nil {
		return err

	} else {
		if err = yaml.Unmarshal([]byte(content), &m); err != nil {
			return err
		}
		SecretsMap = m
	}
	return nil
}

func (h SecretsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	return h.Next.ServeHTTP(w, r)
}
