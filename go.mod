module github.com/freman/caddy-reauth

go 1.12

replace (
	git.apache.org/thrift.git => github.com/apache/thrift v0.0.0-20180902110319-2566ecd5d999
	github.com/go-resty/resty => gopkg.in/resty.v1 v1.12.0
)

require (
	github.com/allegro/bigcache v1.2.1
	github.com/caddyserver/caddy v1.0.1
	github.com/davecgh/go-spew v1.1.1
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/hashicorp/go-getter v1.4.0
	github.com/pkg/errors v0.8.1
	gopkg.in/asn1-ber.v1 v1.0.0-20181015200546-f715ec2f112d // indirect
	gopkg.in/ldap.v2 v2.5.1
	gopkg.in/yaml.v2 v2.2.2
)
