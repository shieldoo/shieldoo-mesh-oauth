package handler

import (
	"net/http"
	"net/url"

	"github.com/shieldoo/shieldoo-mesh-oauth/adminbackend"

	"github.com/shieldoo/shieldoo-mesh-oauth/model"
	"github.com/shieldoo/shieldoo-mesh-oauth/oauthserver"
	"github.com/shieldoo/shieldoo-mesh-oauth/utils"

	log "github.com/sirupsen/logrus"
)

const (
	SERVER_ERROR = "Server error"
)

func HandleOauth(w http.ResponseWriter, r *http.Request, params *model.Params, userDetails *model.SysApiUserDetail) {
	jwt, _, err := oauthserver.CreateToken(params, userDetails)
	if err != nil {
		utils.GeneralResponseTemplate(w, SERVER_ERROR, http.StatusInternalServerError)
		log.Error("OAuth error: ", err)
		return
	}
	log.Debug("OAuth created JWT token: ", jwt)

	if len(params.Code) > 0 {
		err := adminbackend.CreateDeviceLogin(params.Upn, params.Code, params.Provider, params.Audience)
		if err != nil {
			log.Error("Error when calling admin backend: ", err)
			utils.GeneralResponseTemplate(w, SERVER_ERROR, http.StatusInternalServerError)
			return
		}
		utils.RenderTemplate(w, "general", &model.Message{Message: "Now you can close your browser and go back to your application."})
		return
	} else {
		staticAudience := utils.FindStaticAudience(*_cfg, params.Audience)
		// Construct redirect url
		u := &url.URL{}

		redirect := ""
		if params.Redirect != "" {
			redirect = "&redirect=" + params.Redirect
		}

		if staticAudience != nil && staticAudience.Redirect != "" {
			u, err = url.Parse(staticAudience.Redirect + redirect)
		} else {
			u, err = url.Parse("https://" + params.Audience + "." + _cfg.OAuthServer.RedirectDomain + "?from=oauth" + redirect)
		}

		if err != nil {
			utils.GeneralResponseTemplate(w, SERVER_ERROR, http.StatusInternalServerError)
			log.Error("OAuth error: ", err)
			return
		}
		u.Fragment = jwt
		http.Redirect(w, r, u.String(), http.StatusFound)
	}
}
