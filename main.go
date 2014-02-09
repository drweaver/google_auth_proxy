package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
)

const VERSION = "0.0.1"

var (
	showVersion             = flag.Bool("version", false, "print version string")
	httpAddr                = flag.String("http-address", "127.0.0.1:4180", "<addr>:<port> to listen on for HTTP clients")
	redirectUrl             = flag.String("redirect-url", "", "the OAuth Redirect URL. ie: \"https://internalapp.yourcompany.com/oauth2/callback\"")
	clientID                = flag.String("client-id", "", "the Google OAuth Client ID: ie: \"123456.apps.googleusercontent.com\"")
	clientSecret            = flag.String("client-secret", "", "the OAuth Client Secret")
	passBasicAuth           = flag.Bool("pass-basic-auth", true, "pass HTTP Basic Auth information to upstream")
	htpasswdFile            = flag.String("htpasswd-file", "", "additionally authenticate against a htpasswd file. Entries must be created with \"htpasswd -s\" for SHA encryption")
	cookieSecret            = flag.String("cookie-secret", "", "the seed string for secure cookies")
	cookieDomain            = flag.String("cookie-domain", "", "an optional cookie domain to force cookies to")
	googleAppsDomain        = flag.String("google-apps-domain", "", "authenticate against the given google apps domain")
	authenticatedEmailsFile = flag.String("authenticated-emails-file", "", "authenticate against emails via file (one per line)")
	sslDomain               = flag.String("ssl-domain", "", "Enable SSL and use provided domain")
	sslCrt                  = flag.String("ssl-cert", "./ssl.crt", "SSL certificate filename")
	sslCrtKey               = flag.String("ssl-cert-key", "./ssl.key", "SSL Certificate key filename")
	httpsAddr               = flag.String("https-address", "", "Enables SSL on <addr>:<port> to listen on for HTTPS clients")
	sslRedirect             = flag.String("ssl-redirect", "", "redirect traffic (HTTP 301) from http-address to https://<addr>:<port>")
	upstreams               = StringArray{}
)

func init() {
	flag.Var(&upstreams, "upstream", "the http url(s) of the upstream endpoint. If multiple, routing is based on path")
}

func main() {

	flag.Parse()

	// Try to use env for secrets if no flag is set
	if *clientID == "" {
		*clientID = os.Getenv("google_auth_client_id")
	}
	if *clientSecret == "" {
		*clientSecret = os.Getenv("google_auth_secret")
	}
	if *cookieSecret == "" {
		*cookieSecret = os.Getenv("google_auth_cookie_secret")
	}

	if *showVersion {
		fmt.Printf("google_auth_proxy v%s\n", VERSION)
		return
	}

	if len(upstreams) < 1 {
		log.Fatal("missing --upstream")
	}
	if *cookieSecret == "" {
		log.Fatal("missing --cookie-secret")
	}
	if *clientID == "" {
		log.Fatal("missing --client-id")
	}
	if *clientSecret == "" {
		log.Fatal("missing --client-secret")
	}
	if *httpsAddr != "" {
		if *sslDomain == "" {
			log.Fatal("missing --ssl-domain in combination with --https-address")
		}
		if *sslCrt == "" {
			log.Fatal("missing --ssl-cert in combination with --https-address")
		}
		if *sslCrtKey == "" {
			log.Fatal("missing --ssl-cert-key in combination with --https-address")
		}
	}
	if *sslRedirect != "" && *httpAddr == "" {
		log.Fatal("missing --http-address in combination with --ssl-redirect")
	}

	var upstreamUrls []*url.URL
	for _, u := range upstreams {
		upstreamUrl, err := url.Parse(u)
		if err != nil {
			log.Fatalf("error parsing --upstream %s", err.Error())
		}
		upstreamUrls = append(upstreamUrls, upstreamUrl)
	}
	redirectUrl, err := url.Parse(*redirectUrl)
	if err != nil {
		log.Fatalf("error parsing --redirect-url %s", err.Error())
	}

	validator := NewValidator(*googleAppsDomain, *authenticatedEmailsFile)
	oauthproxy := NewOauthProxy(upstreamUrls, *clientID, *clientSecret, validator)
	oauthproxy.SetRedirectUrl(redirectUrl)
	if *googleAppsDomain != "" && *authenticatedEmailsFile == "" {
		oauthproxy.SignInMessage = fmt.Sprintf("using a %s email address", *googleAppsDomain)
	}
	if *htpasswdFile != "" {
		oauthproxy.HtpasswdFile, err = NewHtpasswdFromFile(*htpasswdFile)
		if err != nil {
			log.Fatalf("FATAL: unable to open %s %s", *htpasswdFile, err.Error())
		}
	}
	var listener net.Listener
	if *httpsAddr != "" {
		// SSL
		cert, err := tls.LoadX509KeyPair(*sslCrt, *sslCrtKey)
		if err != nil {
			log.Fatalf("FATAL: Unable to load SSL cert/key: %s", err.Error())
		}
		var TLSconfig *tls.Config
		TLSconfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			ServerName: *sslDomain}
		listener, err = tls.Listen("tcp", *httpsAddr, TLSconfig)
		log.Printf("listening on %s", *httpsAddr)
		
		if *sslRedirect != "" {
			redirectToSSL := func(w http.ResponseWriter, r *http.Request) {
				url := *r.URL
				url.Scheme = "https"
				url.Host = *sslRedirect
				log.Printf("Redirecting %s to %s", r.URL.String(), url.String())
				http.Redirect( w, r, url.String(), http.StatusMovedPermanently )
			}
			go func() {
			    if err := http.ListenAndServe(*httpAddr, http.HandlerFunc(redirectToSSL)); err != nil {
					log.Fatalf("ListenAndServe error: %v", err)
	        	}
			}()
			log.Printf("Redirecting %s to %s", *httpAddr, *httpsAddr)
		}
		
	} else {
		// HTTP
		listener, err = net.Listen("tcp", *httpAddr)
		log.Printf("listening on %s", *httpAddr)
	}
	if err != nil {
		log.Fatalf("FATAL: listen (%s) failed - %s", *httpAddr, err.Error())
	}
	
	server := &http.Server{Handler: oauthproxy}
	err = server.Serve(listener)
	if err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
		log.Printf("ERROR: http.Serve() - %s", err.Error())
	}

	log.Printf("HTTP: closing %s", listener.Addr().String())
}
