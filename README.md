google_auth_proxy
=================

A reverse proxy that provides authentication using Google OAuth2 to validate 
individual accounts, or a whole google apps domain.

Forked from [bitly/google_auth_proxy](https://github.com/bitly/google_auth_proxy) with support added for:
* SSL (thus no need for Nginx)
* HTTP redirect to SSL
* Pre-compiled Raspberry Pi (Raspbian) binaries to be used in 
  conjunction with [Garage Control Service](https://github.com/drweaver/py_garage_server)

Free SSL certificate can be created from [startSSL](http://www.startssl.com/)

[**Download** pre-compiled Raspberry Pi (Raspbian) binaries](https://github.com/drweaver/google_auth_proxy/releases/latest)

## Cross-compiling for Raspberry Pi

On mac or linux:

Firstly, in the GO src directory execute the following command to 
build libraries GO needs to perform the cross-compilation, this only needs to be done once:
```bash
GOOS=linux GOARCH=arm GOARM=5 make.bash
```

Back in the google_auth_proxy folder run:
```bash
GOOS=linux GOARCH=arm GOARM=5 go build
```

Now copy google_auth_proxy binary to your Raspberry Pi for execution

## Architecture

```
                  ___________________       __________
                  |google_auth_proxy| ----> |upstream| 
                  -------------------       ----------
                          ||
                          \/
                  [google oauth2 api]
```


## OAuth Configuration

You will need to register an OAuth application with google, and configure it with Redirect URI(s) for the domain you
intend to run google_auth_proxy on.

1. Visit to Google Api Console https://code.google.com/apis/console/
2. under "API Access", choose "Create an OAuth 2.0 Client ID"
3. Edit the application settings, and list the Redirect URI(s) where you will run your application. For example: 
`https://internalapp.yourcompany.com/oauth2/callback`
4. Make a note of the Client ID, and Client Secret and specify those values as command line arguments

## Command Line Options

```
Usage of ./google_auth_proxy:
  -authenticated-emails-file="": authenticate against emails via file (one per line)
  -client-id="": the Google OAuth Client ID: ie: "123456.apps.googleusercontent.com"
  -client-secret="": the OAuth Client Secret
  -cookie-domain="": an optional cookie domain to force cookies to
  -cookie-secret="": the seed string for secure cookies
  -google-apps-domain="": authenticate against the given google apps domain
  -htpasswd-file="": additionally authenticate against a htpasswd file. Entries must be created with "htpasswd -s" for SHA encryption
  -http-address="127.0.0.1:4180": <addr>:<port> to listen on for HTTP clients
  -pass-basic-auth=true: pass HTTP Basic Auth information to upstream
  -redirect-url="": the OAuth Redirect URL. ie: "https://internalapp.yourcompany.com/oauth2/callback"
  -upstream=[]: the http url(s) of the upstream endpoint. If multiple, routing is based on path
  -version=false: print version string
  -ssl-domain="": the domain registered with your SSL certificate
  -ssl-cert="": the file containing your ssl certificate
  -ssl-cert-key="": the ssl key file
  -https-address="": enables SSL option on given <addr>:<port> to listen on for HTTPS clients
  -ssl-redirect="": the domain:port to redirect incoming requests that go to -http-address
```


## Example Configuration

The command line to run `google_auth_proxy` would look like this:

```bash

export google_auth_client_id=...
export google_auth_secret=...
export google_auth_cookie_secret=...

./google_auth_proxy \
   --redirect-url="https://yourcompany.com/oauth2/callback"  \
   --google-apps-domain="yourcompany.com"  \
   --upstream=http://127.0.0.1:5100/gc/ \
   --ssl-domain="yourcompany.com" \
   --ssl-cert="ssl.crt" \
   --ssl-cert-key="ssl.key" \
   --http-address=":8080" \
   --https-address=":8443" \
   --ssl-redirect="yourcompany.com:443"
```

To use default HTTP (80)/ HTTPS (443) ports the app requires root privileges.  Recommend using IP 
tables to perform internal port forwarding to non-privileged ports.  To redirect port 80 to 8080 
and 443 to 8443 use following commands:

```bash
sudo iptables -A PREROUTING -t nat -p tcp --dport 80 -j REDIRECT --to-port 8080
sudo iptables -A PREROUTING -t nat -p tcp --dport 443 -j REDIRECT --to-port 8443
```

google_auth_proxy can now be run as normal user with arguments --http-address=":8080" 
and/or --https-address=":8443" but still accessed via 80 and 443.  When using this configuration the 
--ssl-redirect argument should match the externally facing domain and port i.e. yourcompany.com:443

## Environment variables

The environment variables `google_auth_client_id`, `google_auth_secret` and `google_auth_cookie_secret` can be used in place of the corresponding command-line arguments.

## Endpoint Documentation

Google auth proxy responds directly to the following endpoints. All other endpoints will be authenticated.

* /oauth2/sign_in - the login page, which also doubles as a sign out page (it clears cookies)
* /oauth2/start - a URL that will redirect to start the oauth cycle
* /oauth2/callback - the URL used at the end of the oauth cycle
