package main

import (
	"io"
	"log"
	"net/http"
	"net/url"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"golang.org/x/oauth2"
)

// _loginHtml is the HTML template for the sso google button
const _loginHtml = `<a href="/login">Google Sign In</a>`

const (
	_oauthURI          = "https://accounts.google.com/o/oauth2/auth"
	_oauthTokenURI     = "https://oauth2.googleapis.com/token"
	_oauthClientID     = "<client-id>"
	_oauthClientSecret = "<client-secret>"
	_oauthScopes       = "https://www.googleapis.com/auth/userinfo.email"
	_oauthRedirectURI  = "http://localhost:8080/login/cb"
	_responseType      = "code"
	_state             = ""
)

var conf = &oauth2.Config{
	ClientID:     _oauthClientID,
	ClientSecret: _oauthClientSecret,
	RedirectURL:  _oauthRedirectURI,
	Scopes:       []string{_oauthScopes},
	Endpoint: oauth2.Endpoint{
		AuthURL:  _oauthURI,
		TokenURL: _oauthTokenURI,
	},
}

func main() {
	e := echo.New()
	registerRoutes(e)

	if err := e.Start(":8080"); err != nil {
		panic(err)
	}

	if err := e.Close(); err != nil {
		panic(err)
	}
}

func registerRoutes(e *echo.Echo) {
	e.Use(middleware.CORS())

	e.GET("/", func(c echo.Context) error {
		return c.HTML(http.StatusOK, _loginHtml)
	})

	e.GET("/login", handleLogin)
	e.GET("/login/cb", handleLoginCallback)
}

// handleLogin is the handler for the /login route
// google sign in button redirects to this route
// this route redirects to google oauth callback(redirect_uri) endpoint
func handleLogin(c echo.Context) error {
	uri, _ := url.Parse(_oauthURI)

	params := uri.Query()
	params.Add("client_id", _oauthClientID)
	params.Add("scope", _oauthScopes)
	params.Add("redirect_uri", _oauthRedirectURI)
	params.Add("response_type", _responseType)
	params.Add("state", _state)

	uri.RawQuery = params.Encode()

	log.Printf("redirecting to %s\n", uri.String())

	return c.Redirect(http.StatusTemporaryRedirect, uri.String())
}

// handleLoginCallback is the handler for the /login/cb route
// google redirects to this route after user has logged in
// this route extracts the access token from the url query
// and calls the google api to get the user info
// and returns the user info in json format
func handleLoginCallback(c echo.Context) error {
	state := c.FormValue("state") // TODO: wtf is that
	code := c.FormValue("code")

	log.Printf("code: %s, state: %s\n", code, state)

	if code == "" {
		reason := c.FormValue("error_reason")
		log.Printf("code is empty, error reason: %s\n", reason)
		return c.String(http.StatusBadRequest, "code is empty")
	}

	token, err := conf.Exchange(c.Request().Context(), code)
	if err != nil {
		log.Printf("failed to exchange code: %s\n", err)
		return c.String(http.StatusBadRequest, "failed to exchange code")
	}
	log.Printf("token: %+v\n", token)

	userInfo, err := getUserInfoWithAccessToken(c, token.AccessToken)
	if err != nil {
		return err
	}

	return c.JSONBlob(http.StatusOK, userInfo)
}

// getUserInfoWithAccessToken calls the google api to get the user info using access token
func getUserInfoWithAccessToken(c echo.Context, accessToken string) ([]byte, error) {
	res, err := http.Get("https://www.googleapis.com/oauth2/v2/userinfo?access_token=" + url.QueryEscape(accessToken))
	if err != nil {
		log.Printf("failed to get user info: %s\n", err)
		return nil, c.String(http.StatusInternalServerError, "failed to get user info")
	}
	defer res.Body.Close()

	resBytes, err := io.ReadAll(res.Body)
	if err != nil {
		log.Printf("failed to read user info: %s\n", err)
		return nil, c.String(http.StatusInternalServerError, "failed to read user info")
	}

	return resBytes, nil
}
