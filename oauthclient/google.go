package oauthclient

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/shieldoo/shieldoo-mesh-oauth/model"
	"github.com/shieldoo/shieldoo-mesh-oauth/utils"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/idtoken"

	log "github.com/sirupsen/logrus"
)

var oauthGoogleConfig *oauth2.Config

func InitGoogle(cfg *utils.Config) {
	oauthGoogleConfig = &oauth2.Config{
		RedirectURL:  _cfg.Server.Uri + "/" + _cfg.Google.CallbackUrl,
		ClientID:     _cfg.Google.ClientId,
		ClientSecret: _cfg.Google.ClientSecret,
		Scopes:       []string{"openid", "email"},
		Endpoint:     google.Endpoint,
	}
}

func HandleGoogleCallback(request *http.Request) (*model.Params, error) {

	code := request.FormValue("code")
	tokenResponse, error := exchangeCode(code, oauthGoogleConfig)
	if error != nil {
		return nil, error
	}

	idToken, error := extractIdToken(tokenResponse)
	if error != nil {
		return nil, error
	}

	payload, error := validate(idToken, _cfg.Google.ClientId)
	if error != nil {
		return nil, error
	}

	state := request.FormValue("state")
	params, error := decodeParams(state)
	if error != nil {
		return nil, error
	}

	params = populateUpn(params, payload)

	return params, nil
}

func GetAuthorizeGoogleUrl(params *model.Params) (string, error) {
	state, err := json.Marshal(params)
	if err != nil {
		return "", err
	}

	returnUrl := oauthGoogleConfig.AuthCodeURL(
		string(state), oauth2.AccessTypeOffline,
		oauth2.SetAuthURLParam("prompt", "select_account"),
		oauth2.SetAuthURLParam("response_mode", "form_post"), //Not supported but allowed by google. More secure.
	)

	log.Debug("URL prepared to redirect: " + returnUrl)
	return returnUrl, nil
}

func getClaimValue(claimName string, payload *idtoken.Payload) string {
	return payload.Claims[claimName].(string)
}

func validate(idToken string, audience string) (*idtoken.Payload, error) {
	payload, error := idtoken.Validate(context.Background(), idToken, audience)
	if error != nil {
		log.Error(error)
		return nil, error
	}
	return payload, error
}

func populateUpn(params *model.Params, payload *idtoken.Payload) *model.Params {
	upn := getClaimValue("email", payload)
	log.WithFields(log.Fields{
		"upn": upn,
	}).Info("User found in token")
	params.Upn = upn

	return params
}
