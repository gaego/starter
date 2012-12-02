package app

import (
	"html/template"
	"net/http"
)

func init() {
	http.HandleFunc("/login", login)
	http.HandleFunc("/", home)
}

var App = map[string]string{
	"Title":               "GAEGo Starter",
	"Description":         "",
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
