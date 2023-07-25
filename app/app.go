package app

import (
	"encoding/json"
	"errors"
	"net/http"
	"regexp"

	"github.com/shieldoo/shieldoo-mesh-oauth/oauthserver"

	"github.com/gorilla/mux"
	nebulaAuthHandler "github.com/shieldoo/shieldoo-mesh-oauth/handler"
	"github.com/shieldoo/shieldoo-mesh-oauth/model"
	"github.com/shieldoo/shieldoo-mesh-oauth/oauthclient"
	"github.com/shieldoo/shieldoo-mesh-oauth/utils"
	log "github.com/sirupsen/logrus"
)

var codeValidRegex = regexp.MustCompile("^[a-zA-Z0-9-_:]{32,72}$")
var audienceValidRegex = regexp.MustCompile("^[a-zA-Z][a-zA-Z0-9-]{2,63}$")
var providerValidRegex = regexp.MustCompile("^(microsoft|google)$")
var _cfg *utils.Config

func validateRegex(regex *regexp.Regexp, value string) (bool, error) {
	if regex.MatchString(value) {
		return true, nil
	} else {
		return false, errors.New("not valid value")
	}
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	log.Debug("Endpoint Hit (GET): / ")
	code := r.URL.Query().Get("state")
	if _, err := validateRegex(codeValidRegex, code); err != nil {
		code = ""
	}
	redirect := r.URL.Query().Get("redirect")
	audience := r.URL.Query().Get("audience")
	if audience == "" && code != "" {
		utils.GeneralResponseTemplate(w, "Missing audience parameter when device login active.", http.StatusBadRequest)
	}
	if audience == "" {
		audience = _cfg.OAuthServer.DefaultAudience
	}
	if _, err := validateRegex(audienceValidRegex, audience); err != nil {
		utils.GeneralResponseTemplate(w, "Missing or invalid audience parameter", http.StatusBadRequest)
		return
	}
	utils.RenderTemplate(w, "login", &model.Params{Code: code, Audience: audience, Redirect: redirect})
}

func authorizeHandler(w http.ResponseWriter, r *http.Request) {
	log.Debug("Endpoint Hit (POST): /authorize")
	if err := r.ParseForm(); err != nil {
		utils.GeneralResponseTemplate(w, err.Error(), http.StatusBadRequest)
		return
	}
	code := r.Form.Get("code")
	if _, err := validateRegex(codeValidRegex, code); err != nil {
		log.Info("Invalid or missing code, code will be empty.")
		code = ""
	}
	redirect := r.Form.Get("redirect")
	audience := r.Form.Get("audience")
	if _, err := validateRegex(audienceValidRegex, audience); err != nil {
		utils.GeneralResponseTemplate(w, "Missing or invalid audience parameter", http.StatusBadRequest)
		return
	}
	provider := r.Form.Get("provider")
	if _, err := validateRegex(providerValidRegex, provider); err != nil {
		utils.GeneralResponseTemplate(w, "Missing or invalid provider parameter", http.StatusBadRequest)
		return
	}
	params := &model.Params{
		Code:     code,
		Audience: audience,
		Provider: provider,
		Redirect: redirect,
	}
	var url string
	var err error
	switch provider {
	case "microsoft":
		url, err = oauthclient.GetAuthorizeMicrosoftUrl(params)
	case "google":
		url, err = oauthclient.GetAuthorizeGoogleUrl(params)
	}

	if err != nil || url == "" {
		log.Error(err)
		utils.GeneralResponseTemplate(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	log.Debug("Endpoint Hit (POST): /authorize with result redirect " + url)
	http.Redirect(w, r, url, http.StatusFound)
}

// TODO: Refactor: Duplicity with google handler
func callbackMicrosoftHandler(w http.ResponseWriter, request *http.Request) {
	log.Debug("Endpoint Hit (POST): /callback/microsoft")

	params, err := oauthclient.HandleMicrosoftCallback(request)

	if err != nil {
		http.Error(w, "Error when processing request.", http.StatusUnauthorized)
		return
	}

	userDetails, err := nebulaAuthHandler.HandleAuthorization(w, params.Upn, params)
	if err == nil {
		nebulaAuthHandler.HandleOauth(w, request, params, userDetails)
	}
}

func callbackGoogleHandler(w http.ResponseWriter, request *http.Request) {
	log.Debug("Endpoint Hit (POST): /callback/google")

	params, err := oauthclient.HandleGoogleCallback(request)
	if err != nil {
		http.Error(w, "Error when processing request.", http.StatusUnauthorized)
		return
	}

	userDetails, err := nebulaAuthHandler.HandleAuthorization(w, params.Upn, params)
	if err == nil {
		nebulaAuthHandler.HandleOauth(w, request, params, userDetails)
	}
}

func oauthCerts(w http.ResponseWriter, r *http.Request) {
	log.Debug("Endpoint Hit (GET): /oauth2/v1/certs")
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusOK)
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", " ")
	if err := encoder.Encode(oauthserver.GenerateJwks()); err != nil {
		log.Error("json error: ", err)
	}
}

func openIdConfiguration(w http.ResponseWriter, r *http.Request) {
	log.Debug("Endpoint Hit (GET): /.well-known/openid-configuration")
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusOK)
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", " ")
	if err := encoder.Encode(oauthserver.GenerateOpenIdConfiguration()); err != nil {
		log.Error("json error: ", err)
	}
}

func Run(cfg *utils.Config) {
	_cfg = cfg
	log.Info("Starting server at port: " + cfg.Server.Port)
	myRouter := mux.NewRouter()
	myRouter.HandleFunc("/", loginHandler).Methods("GET")
	myRouter.HandleFunc("/authorize", authorizeHandler).Methods("POST")
	myRouter.HandleFunc("/callback/microsoft", callbackMicrosoftHandler).Methods("POST")
	myRouter.HandleFunc("/callback/google", callbackGoogleHandler).Methods("POST")
	myRouter.HandleFunc("/oauth2/v1/certs", oauthCerts).Methods("GET")
	myRouter.HandleFunc("/.well-known/openid-configuration", openIdConfiguration).Methods("GET")

	log.Fatal(http.ListenAndServe(":"+cfg.Server.Port, myRouter))
}
