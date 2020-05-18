# reauth

Another authentication plugin for CaddyServer (v1)

For CaddyServer V2 Please [caddy2-reauth](https://github.com/freman/caddy2-reauth)

## Contents

- [reauth](#reauth)
  * [Abstract](#abstract)
  * [Supported backends](#supported-backends)
  * [Supported failure handlers](#supported-failure-handlers)
  * [Configuration](#configuration)
    + [Spaces in configuration](#spaces-in-configuration)
  * [Backends](#backends)
    + [Simple](#simple)
    + [Upstream](#upstream)
    + [Refresh](#refresh)
    + [GitlabCI](#gitlabci)
    + [LDAP](#ldap)
  * [Failure handlers](#failure-handlers)
    + [HTTPBasic](#httpbasic)
    + [Redirect](#redirect)
    + [Status](#status)
  * [Todo](#todo)
  * [Other notes](#other-notes)

## Abstract

Provides a common basis for various and multiple authentication systems. This came to be as we wanted to dynamically authenticate our
docker registry against gitlab-ci and avoid storing credentials in gitlab while still permitting users to log in with their own credentials.

## Supported backends

The following backends are supported.

* [Simple](#simple)
* [Upstream](#upstream)
* [Refresh](#refresh)
* [GitlabCI](#gitlabci)
* [LDAP](#ldap)

With more to come...

## Supported failure handlers

The following failure handlers are supported.

* [HTTPBasic](#httpbasic)
* [Redirect](#redirect)
* [Status](#status)

## Configuration

The core of the plugin supports the following arguments:

| Parameter-Name    | Description                                                                                        |
| ------------------|----------------------------------------------------------------------------------------------------|
| path              | the path to protect, may be repeated but be aware of strange interactions with `except` (required) |
| except            | sub path to permit unrestricted access to (optional, can be repeated)                              |
| failure           | what to do on failure (see failure handlers, default is [HTTPBasic](#httpbasic))                   |

Example:
```
	reauth {
		path /
		except /public
		except /not_so_secret
	}
```

Along with these two arguments you are required to specify at least one backend.

### Spaces in configuration

Through experimentation by [@mh720 (Mike Holloway)](https://github.com/mh720) it has been discovered that if you need spaces in your configuration that the best
bet is to use unicode escaping.

For example:
```
OU=GROUP\u0020NAME
```

I imagine this would allow you to escape any character you need this way including quotes.

## Backends

### Simple

This is the simplest plugin, taking just a list of username=password[,username=password].

Example:
```
	simple user1=password1,user2=password2
```

### Upstream

Authentication against an upstream http server by performing a http basic authenticated request and checking the response for a http 200 OK status code. Anything other than a 200 OK status code will result in a failure to authenticate.

Parameters for this backend:

| Parameter-Name    | Description                                                                              |
| ------------------|------------------------------------------------------------------------------------------|
| url               | http/https url to call                                                                   |
| skipverify        | true to ignore TLS errors (optional, false by default)                                   |
| timeout           | request timeout (optional 1m by default, go duration syntax is supported)                |
| follow            | follow redirects (disabled by default as redirecting to a login page might cause a 200)  |
| cookies           | true to pass cookies to the upstream server                                              |
| match             | used with follow, match string against the redirect url, if found then not logged in     |

Examples
```
	upstream url=https://google.com,skipverify=true,timeout=5s
  upstream url=https://google.com,skipverify=true,timeout=5s,follow=true,match=login
```

### Refresh

Authentication with Refresh Token against configurable endpoints with response caching and cache entry expiration times. If failure conditions in the configuration file are met a 401 is returned otherwise result will be successful.
This module is designed to be used with the [caddy-secrets](https://github.com/startsmartlabs/caddy-secrets) plugin, a yaml file with a `reauth` object with an `endpoints` array will hold configurations for endpoints and how they work together for auth service.

Parameters for this backend:

| Parameter-Name    | Description                                                                              |
| ------------------|------------------------------------------------------------------------------------------|
| url               | http/https url to call                                                                   |
| skipverify        | true to ignore TLS errors (optional, false by default)                                   |
| timeout           | request timeout (optional 1m by default, go duration syntax is supported)                |
| follow            | follow redirects (disabled by default as redirecting to a login page might cause a 200)  |
| cookies           | true to pass cookies to the upstream server                                              |
| limit             | int to set response size limit for endpoint requests (default 1000)                      |
| lifetime          | time interval that a file cached by this module will remain valid (default 3 hours)      |
| cleaninterval     | time interval to clean cache of expired entries (default 1 second)                       |

Examples

- Caddyfile
```
	refresh url=https://example.com,skipverify=true,timeout=5s,lifetime=3h,cleaninterval=1s,limit=1000
```

- Secrets file
```
reauth:
  client_authorization: 1                             # authorization flag (required) - 0/1 whether to check for Authorization header, 2 will throw 500 if missing
                                                          Authorization access token stored in 'ResultsMap' under 'client_token' key
  endpoints                                           # endpoints array (required)
    - name: refresh                                   # endpoint of name 'refresh' (required)
      url: null                                       
      path: "/access_token"
      method: POST                                    # auth request method (required) - at the moment only POST and GET are handled (value must be in caps)
      data:                                           # data array (required)
        - key: grant_type
          value: refresh_token
        - key: refresh_token                          # object with 'refresh_token' key (required)
          value: <refresh token to get access token>  # value (required) - holds actual refresh token to request access token with
      cachekey: refresh_token
      headers:
        - key: Content-Type
          value: "application/x-www-form-urlencoded"
      skipverify: true
      cookies: true
      responsekey: jwt_token
      failures:
        - validation: equality                        # there are 3 types of validation, 'equality' will have auth fail if
          key: message                                # response body value under failure object key equality failure object value
          value: Forbidden
          valuemessage: false
          message: "Refresh access token failed"
                                                      # access token is stored in 'ResultsMap' under 'refresh' key
                                                      
    - name: security_context                          # endpoint responses get stored in 'ResultsMap' under the name of the endpoint
      url: https://different.example.com              # url value should be set if endpoint uses different url than one in Caddyfile
      path: "/security_context"                       # path is concatenated after url for request 
      method: GET                                     # request method, GET will put data params in query, POST will encode form
      data:                                           # data needed for request
        - key: access_token
          value: "{client_token}"                     # surrounding keys with {}'s will have them replaced by values in 'ResultsMap'
      cachekey: client_token                          # cache entry key
      headers:                                        # keys and values to set on endpoint request headers
        - key: Authorization                          
          value: "Bearer {refresh}"                   # surrounding keys with {}'s will have them replaced by values in 'ResultsMap' 
      skipverify: true                                # whether endpoint request should use Caddyfile skipverify configuration
      cookies: true                                   # whether endpoint request should use Caddyfile cookies configuration
      responsekey: null                               # if set, the key will be used to pull value from endpoint response
      failures:
        - validation: presence                        # 'presence' validation will have auth fail if response body has failure object key
          key: error
          value: ~
          valuemessage: true                          # if valuemessage bool is true, response object value under failure object key
          message: "Security context error: "             is concatenated to failure message
        - validataion: status                         # 'status' validation will have auth fail if endpoint response status
          key: ~                                          matches failure object value
          value: 401
          valuemessage: false
          message: "Security context unauthorized"
  resultkey: security_context                         # last endpoint response stored in 'ResultsMap' is passed down caddy filter chain
                                                          in a query param with the key named after 'resultkey' value
```


### GitlabCI

Authenticate against Gitlab as the gitlab-ci-user for the purposes of letting the gitlab-ci access otherwise protected resources without storing credentials in gitlab or gitlab-ci.yml. Works basically like the [Upstream]#upstream backend except the username you provide is the project path

Parameters for this backend:

| Parameter-Name    | Description                                                                              |
| ------------------|------------------------------------------------------------------------------------------|
| url               | http/https url to call                                                                   |
| skipverify        | true to ignore TLS errors (optional, false by default)                                   |
| timeout           | request timeout (optional 1m by default, go duration syntax is supported)                |

Example
```
	gitlabci url=https://gitlab.example.com,skipverify=true,timeout=5s
```

Example of logging in via gitlab-ci.yml

```
	docker login docker.example.com -u "$CI_PROJECT_PATH" -p "$CI_BUILD_TOKEN"
```

### LDAP

Authenticate against a specified LDAP server - for example a Microsoft AD server.

Parameters for this backend:

| Parameter-Name   | Description                                                                                                              |
| ------------------|-------------------------------------------------------------------------------------------------------------------------|
| url              | url, required - i.e. ldap://ldap.example.com:389                                                                         |
| tls              | should StartTLS be used? (default false)                                                                                 |
| username         | (read-only) bind username - i.e. ldap-auth                                                                               |
| password         | the password for the bind username                                                                                       |
| insecure         | true to ignore TLS errors (optional, false by default)                                                                   |
| timeout          | request timeout (optional 1m by default, go duration syntax is supported)                                                |
| base             | Search base, for example "OU=Users,OU=Company,DC=example,DC=com"                                                         |
| filter           | Filter the users, eg "(&(memberOf=CN=group,OU=Users,OU=Company,DC=example,DC=com)(objectClass=user)(sAMAccountName=%s))" |
| principal_suffix | suffix to append to usernames (eg: @example.com)                                                                         |
| pool_size        | size of the connection pool, default is 10                                                                               |

Example
```
	ldap url=ldap://ldap.example.com:389,timeout=5s,base="OU=Users,OU=Company,DC=example,DC=com",filter="(&(memberOf=CN=group,OU=Users,OU=Company,DC=example,DC=com)(objectClass=user)(sAMAccountName=%s))"
```

## Failure handlers

### HTTPBasic

This is the default failure handler and is by default configured to send the requested host as the realm

Parameters for this handler:

| Parameter-Name    | Description                                                                              |
| ------------------|------------------------------------------------------------------------------------------|
| realm             | name of the realm to authenticate against - defaults to host                             |

Example
```
	failure  basicauth realm=example.org
```

### Redirect

Redirect the user, perhaps to a login page?

Parameters for this handler:

| Parameter-Name    | Description                                                                              |
| ------------------|------------------------------------------------------------------------------------------|
| target            | target url for the redirection, supports {uri} for redirection (required)                |
| code              | the http status code to use, defaults to 302                                             |

Example
```
	failure redirect target=example.org,code=303
```

Example with uri
```
	failure redirect target=/auth?redir={uri},code=303
```

### Status

Simplest possible failure handler, return http status $code

Parameters for this handler:

| Parameter-Name    | Description                                                                              |
| ------------------|------------------------------------------------------------------------------------------|
| code              | the http status code to use, defaults to 401                                             |

Example
```
	failure status code=418
```

## Todo

Modularise the failure handlers...

## Other notes

* Have embedded [https://github.com/startsmartlabs/caddy-secrets](https://github.com/startsmartlabs/caddy-secrets) in [lib/caddy-secrets](lib/caddy-secrets) for easier maintenance.