package app

import (
	"github.com/gaego/auth"
	"github.com/gaego/auth/appengine_openid"
	"github.com/gaego/auth/password"
	"html/template"
	"net/http"
)

func init() {
	// Auth

	// Default config; shown here for demonstration.
	auth.BaseURL = "/-/auth/"
	auth.LoginURL = "/login"
	auth.LogoutURL = "/-/auth/logout"
	auth.SuccessURL = "/"

	// Register the providers
	auth.Register("appengine_openid", appengine_openid.New())
	auth.Register("password", password.New())

	// Handlers
	http.HandleFunc("/login", login)
	http.HandleFunc("/signup", signup)
	http.HandleFunc("/", home)
}

var App = map[string]string{
	"Title":               "GAEGo Starter",
	"Description":         "Google App Engine Starter Application Targeting the Go Runtime",
	"Author":              "Scotch Media",
	"GoogleAnalyticsCode": "",
}

func tmplMap() map[string]interface{} {
	m := make(map[string]interface{})
	m["App"] = App
	return m
}

var (
	homeTmpl = template.Must(template.ParseFiles("templates/base.html",
		"templates/home.html"))
	loginTmpl = template.Must(template.ParseFiles("templates/base.html",
		"templates/login.html"))
	signupTmpl = template.Must(template.ParseFiles("templates/base.html",
		"templates/signup.html"))
)

func home(w http.ResponseWriter, r *http.Request) {
	m := tmplMap()
	if err := homeTmpl.Execute(w, m); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func login(w http.ResponseWriter, r *http.Request) {
	m := tmplMap()
	if err := loginTmpl.Execute(w, m); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func signup(w http.ResponseWriter, r *http.Request) {
	m := tmplMap()
	if err := signupTmpl.Execute(w, m); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
