// Copyright 2011 The goauth2 Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This program makes a call to the specified API, authenticated with OAuth2.
// a list of example APIs can be found at https://code.google.com/oauthplayground/
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	"code.google.com/p/goauth2/oauth"
)

var (
	clientId     = flag.String("id", "", "Client ID")
	clientSecret = flag.String("secret", "", "Client Secret")
	authURL      = flag.String("auth", "https://accounts.google.com/o/oauth2/auth", "Authorization URL")
	tokenURL     = flag.String("token", "https://accounts.google.com/o/oauth2/token", "Token URL")
	apiURL       = flag.String("api", "https://www.googleapis.com/auth/userinfo.profile", "API URL")
	redirectURL  = flag.String("redirect", "http://localhost/", "Redirect URL")
	apiRequest   = flag.String("req", "https://www.googleapis.com/oauth2/v1/userinfo", "API request")
	code         = flag.String("code", "", "Authorization Code")
	cachefile    = flag.String("cachefile", "request.token", "Token cache file")
	authparam    = flag.String("ap", "", "Authorization parameter")
	cache        = flag.Bool("cache", false, "Read token from cache")

	tokenCache oauth.CacheFile
)

const usageMsg = `
You must either specify both -id and -secret, or -cache to use saved tokens

To obtain client id and secret, see the "OAuth 2 Credentials" section under
the "API Access" tab on this page: https://code.google.com/apis/console/

After you receive a valid code, specify it using -code; then subsequent calls only need -cache
`

func main() {
	flag.Parse()
	if (*clientId == "" || *clientSecret == "") && !*cache {
		flag.Usage()
		fmt.Fprint(os.Stderr, usageMsg)
		return
	}
	// Set up a configuration
	config := &oauth.Config{
		ClientId:     *clientId,
		ClientSecret: *clientSecret,
		Scope:        *apiURL,
		AuthURL:      *authURL,
		TokenURL:     *tokenURL,
		RedirectURL:  *redirectURL,
	}

	// Step one, get an authorization code from the data provider.
	// ("Please ask the user if I can access this resource.")
	if *code == "" && !*cache {
		url := config.AuthCodeURL("")
		fmt.Println("Visit this URL to get a code, then run again with -code=YOUR_CODE\n")
		fmt.Println(url)
		return
	}

	// Set up a Transport with our config, define the cache
	t := &oauth.Transport{Config: config}
	tokenCache = oauth.CacheFile(*cachefile)

	// Step two, exchange the authorization code for an access token.
	// Cache the token for later use
	// ("Here's the code you gave the user, now give me a token!")
	if !*cache {
		tok, err := t.Exchange(*code)
		if err != nil {
			log.Fatal("Exchange:", err)
		}
		err = tokenCache.PutToken(tok)
		if err != nil {
			log.Fatal("Cache write:", err)
		}
		fmt.Printf("Token is cached in %v\n", tokenCache)
		return
		// We needn't return here; we could just use the Transport
		// to make authenticated requests straight away.
		// The process has been split up to demonstrate how one might
		// restore Credentials that have been previously stored.
	} else {
		// Step three, make the actual request using the cached token to authenticate.
		// ("Here's the token, let me in!")
		ctoken, err := tokenCache.Token()
		if err != nil {
			log.Fatal("Cache read:", err)
		}
		t.Token = &oauth.Token{AccessToken: ctoken.AccessToken}
		// Tack on the extra parameters, if specified.
		if *authparam != "" {
			*apiRequest += *authparam + ctoken.AccessToken
		}
	}

	// Make the request.
	r, err := t.Client().Get(*apiRequest)
	if err != nil {
		log.Fatal("Request:", err)
	}
	defer r.Body.Close()
	// Write the response to standard output.
	io.Copy(os.Stdout, r.Body)
	fmt.Println()
}
