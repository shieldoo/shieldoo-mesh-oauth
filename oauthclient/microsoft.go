package oauthclient

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/shieldoo/shieldoo-mesh-oauth/model"
	"github.com/shieldoo/shieldoo-mesh-oauth/utils"
	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/microsoft"

	"github.com/dgrijalva/jwt-go"
	"github.com/lestrrat-go/jwx/jwk"
)

var cachedKey *rsa.PublicKey = nil
var cachedKid = ""
var keyCachedTimestamp = time.Now().UTC()

var issuerRegexps []*regexp.Regexp

var oauthMicrosoftConfig *oauth2.Config

//TODO: Refactor into struct

func InitMicrosoft(cfg *utils.Config) {
	_cfg = cfg
	for _, issuer := range _cfg.Aad.Issuers {
		r, _ := regexp.Compile(issuer)
		issuerRegexps = append(issuerRegexps, r)
	}

	oauthMicrosoftConfig = &oauth2.Config{
		RedirectURL:  _cfg.Server.Uri + "/" + _cfg.Aad.CallbackUrl,
		ClientID:     _cfg.Aad.ClientId,
		ClientSecret: _cfg.Aad.ClientSecret,
		Scopes:       []string{"openid", "email", "profile"},
		Endpoint:     microsoft.AzureADEndpoint(""), //TODO: Tenant
	}
}

func HandleMicrosoftCallback(request *http.Request) (*model.Params, error) {

	code := request.FormValue("code")
	var tokenResponse, err = exchangeCode(code, oauthMicrosoftConfig)
	if err != nil {
		return nil, err
	}

	idToken, err := extractIdToken(tokenResponse)
	if err != nil {
		return nil, err
	}

	payload, err := validateMicrosoft(idToken)
	if err != nil {
		return nil, err
	}

	state := request.FormValue("state")
	params, err := decodeParams(state)
	if err != nil {
		return nil, err
	}

	params, err = populateMicrosoftName(params, payload)
	if err != nil {
		return nil, err
	}
	params = populateMicrosoftUpn(params, payload)
	params, err = pupulateMicrosoftTenant(params, payload)
	if err != nil {
		return nil, err
	}

	return params, nil
}

func GetAuthorizeMicrosoftUrl(params *model.Params) (string, error) {
	state, err := json.Marshal(params)
	if err != nil {
		return "", err
	}

	returnUrl := oauthMicrosoftConfig.AuthCodeURL(
		string(state), oauth2.AccessTypeOffline,
		oauth2.SetAuthURLParam("prompt", "select_account"),
		oauth2.SetAuthURLParam("response_mode", "form_post"),
	)

	if params.Tenant != "" {
		returnUrl = strings.Replace(returnUrl, "/common/", "/"+params.Tenant+"/", 1)
	}

	log.Debug("URL prepared to redirect: " + returnUrl)
	return returnUrl, nil
}

func certCacheExpired() bool {
	return keyCachedTimestamp.Add(3600 * time.Second).Before(time.Now().UTC())
}

func getKey(token *jwt.Token) (interface{}, error) {
	kid, ok := token.Header["kid"].(string)
	if !ok {
		return nil, fmt.Errorf("kid header not found")
	}

	if cachedKid != kid || certCacheExpired() { //TODO: Use jwk cache instead
		set, err := jwk.Fetch(context.Background(), _cfg.Aad.JwksUri)
		if err != nil {
			return nil, err
		}

		keys, ok := set.LookupKeyID(kid)
		if !ok {
			return nil, fmt.Errorf("key not found")
		}

		key := &rsa.PublicKey{}
		err = keys.Raw(key)
		if err != nil {
			return nil, fmt.Errorf("could not parse pubkey")
		}

		cachedKey = key
		keyCachedTimestamp = time.Now().UTC()
	}

	return cachedKey, nil
}

func validateMicrosoft(token string) (*jwt.Token, error) {
	parsedToken, err := jwt.Parse(token, getKey)
	if err != nil {
		log.Error("JWT: Invalid token: ", err)
		return nil, err
	}

	claimError := parsedToken.Claims.(jwt.MapClaims).Valid()
	if claimError != nil {
		log.Error("JWT validate: Invalid claims: ", claimError)
		return nil, claimError
	}

	if !parsedToken.Claims.(jwt.MapClaims).VerifyAudience(_cfg.Aad.ClientId, true) {
		log.Error("JWT validate: Invalid audience")
		return nil, fmt.Errorf("invalid audience")
	}

	validIssuer := false
	// Validating using regexp is enough, because we have statically defined JWKS uri (only signed by Microsoft)
	for _, re := range issuerRegexps {
		iss := parsedToken.Claims.(jwt.MapClaims)["iss"].(string)
		if re.MatchString(iss) {
			validIssuer = true
			log.Debug("Issuer accepted: " + iss)
			break
		}
	}

	if !validIssuer {
		log.Error("JWT validate: Invalid issuer")
		return nil, fmt.Errorf("invalid issuer")
	}

	return parsedToken, nil
}

func getUserNameFromMicrosoftToken(jwttoken *jwt.Token) string {
	if val, ok := jwttoken.Claims.(jwt.MapClaims)["upn"]; ok {
		return val.(string)
	}
	if val, ok := jwttoken.Claims.(jwt.MapClaims)["unique_name"]; ok {
		return val.(string)
	}
	return jwttoken.Claims.(jwt.MapClaims)["preferred_username"].(string)
}

func getMicrosoftClaimValue(jwttoken *jwt.Token, claimName string) (string, error) {
	if val, ok := jwttoken.Claims.(jwt.MapClaims)[claimName]; ok {
		return val.(string), nil
	} else {
		return "", fmt.Errorf("claim '%s' not found", claimName)
	}
}

func populateMicrosoftName(params *model.Params, payload *jwt.Token) (*model.Params, error) {
	name, err := getMicrosoftClaimValue(payload, "name")
	if err != nil {
		log.Error(err)
		return nil, err
	}

	log.WithFields(log.Fields{
		"name": name,
	}).Info("User Full Name in token")
	params.Name = name

	return params, nil
}

func populateMicrosoftUpn(params *model.Params, payload *jwt.Token) *model.Params {
	upn := getUserNameFromMicrosoftToken(payload)
	log.WithFields(log.Fields{
		"upn": upn,
	}).Info("User found in token")
	params.Upn = upn

	return params
}

func pupulateMicrosoftTenant(params *model.Params, payload *jwt.Token) (*model.Params, error) {
	tenant, err := getMicrosoftClaimValue(payload, "tid")

	if err != nil {
		log.Error(err)
		return nil, err
	}

	log.WithFields(log.Fields{
		"tenant": tenant,
	}).Info("Found tenant to user")
	params.Tenant = tenant

	return params, nil
}
