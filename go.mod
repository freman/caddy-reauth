module github.com/freman/caddy-reauth

go 1.12

replace (
	git.apache.org/thrift.git => github.com/apache/thrift v0.0.0-20180902110319-2566ecd5d999
	github.com/go-resty/resty => gopkg.in/resty.v1 v1.12.0
)

require (
	cloud.google.com/go/storage v1.0.0 // indirect
	github.com/allegro/bigcache v1.2.1
	github.com/aws/aws-sdk-go v1.24.2 // indirect
	github.com/bifurcation/mint v0.0.0-20190901182352-1218c79bb0c0 // indirect
	github.com/caddyserver/caddy v1.0.3
	github.com/cenkalti/backoff v2.2.1+incompatible // indirect
	github.com/davecgh/go-spew v1.1.1
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/go-acme/lego v2.7.2+incompatible // indirect
	github.com/hashicorp/go-cleanhttp v0.5.1 // indirect
	github.com/hashicorp/go-getter v1.4.0
	github.com/hashicorp/go-version v1.2.0 // indirect
	github.com/klauspost/cpuid v1.2.1 // indirect
	github.com/lucas-clemente/quic-go v0.12.0 // indirect
	github.com/mholt/certmagic v0.7.2 // indirect
	github.com/miekg/dns v1.1.17 // indirect
	github.com/pkg/errors v0.8.1
	github.com/russross/blackfriday v2.0.0+incompatible // indirect
	github.com/shurcooL/sanitized_anchor_name v1.0.0 // indirect
	github.com/ulikunitz/xz v0.5.6 // indirect
	go.opencensus.io v0.22.1 // indirect
	golang.org/x/build v0.0.0-20190111050920-041ab4dc3f9d // indirect
	golang.org/x/exp v0.0.0-20190919035709-81c71964d733 // indirect
	golang.org/x/net v0.0.0-20190918130420-a8b05e9114ab // indirect
	golang.org/x/sys v0.0.0-20190919044723-0c1ff786ef13 // indirect
	golang.org/x/tools v0.0.0-20190920023704-c426260dee6e // indirect
	google.golang.org/api v0.10.0 // indirect
	google.golang.org/appengine v1.6.2 // indirect
	google.golang.org/genproto v0.0.0-20190916214212-f660b8655731 // indirect
	google.golang.org/grpc v1.23.1 // indirect
	gopkg.in/asn1-ber.v1 v1.0.0-20181015200546-f715ec2f112d // indirect
	gopkg.in/ldap.v2 v2.5.1
	gopkg.in/yaml.v2 v2.2.2
)
