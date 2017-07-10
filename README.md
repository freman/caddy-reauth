# reauth

Another authentication plugin for CaddyServer

## Abstract

Provides a common basis for various and multiple authentication systems. This came to be as we wanted to dynamically authenticate our
docker registry against gitlab-ci and avoid storing credentials in gitlab while still permitting users to log in with their own credentials.

## Supported backends

The following backends are supported.

* [Simple](#simple)
* [Upstream](#upstream)
* [GitlabCI](#gitlabci)

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

Example
```
	upstream url=https://google.com,skipverify=true,timeout=5s
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
	gitlab url=https://gitlab.example.com,skipverify=true,timeout=5s
```

Example of logging in via gitlab-ci.yml

```
	docker login docker.example.com -u "$CI_PROJECT_PATH" -p "$CI_BUILD_TOKEN"
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
	failure httpbasic realm=example.org
```

### Redirect

Redirect the user, perhaps to a login page?

Parameters for this handler:

| Parameter-Name    | Description                                                                              |
| ------------------|------------------------------------------------------------------------------------------|
| target            | target url for the redirection (required)                                                |
| code              | the http status code to use, defaults to 302                                             |

Example
```
	failure redirect target=example.org,code=303
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
