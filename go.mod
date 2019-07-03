module github.com/freman/caddy-reauth

go 1.12

replace github.com/go-resty/resty => gopkg.in/resty.v1 v1.12.0

require (
	github.com/allegro/bigcache v1.2.1
	github.com/caddyserver/caddy v1.0.1
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/hashicorp/go-getter v1.3.0
	github.com/pkg/errors v0.8.1
	gopkg.in/asn1-ber.v1 v1.0.0-20181015200546-f715ec2f112d // indirect
	gopkg.in/ldap.v2 v2.5.1
	gopkg.in/yaml.v2 v2.2.2
)
