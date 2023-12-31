package utils

import (
	"html/template"
	"net/http"

	"github.com/shieldoo/shieldoo-mesh-oauth/model"
)

var templates = template.Must(template.ParseFiles("templates/login.html", "templates/general.html", "templates/basicauth.html"))

func RenderTemplate(w http.ResponseWriter, tmpl string, data interface{}) {
	RenderTemplateWithResultCode(w, tmpl, data, http.StatusOK)
}

func RenderTemplateWithResultCode(w http.ResponseWriter, tmpl string, data interface{}, code int) {
	w.WriteHeader(code)
	err := templates.ExecuteTemplate(w, tmpl+".html", data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func GeneralResponseTemplate(w http.ResponseWriter, error string, code int) {
	RenderTemplateWithResultCode(w, "general", model.Message{Message: error}, code)
}
