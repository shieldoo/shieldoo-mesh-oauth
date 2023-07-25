package adminbackend

import (
	"errors"
	"fmt"
	"github.com/go-resty/resty/v2"
	"github.com/shieldoo/shieldoo-mesh-oauth/model"
	"github.com/shieldoo/shieldoo-mesh-oauth/oauthserver"
	log "github.com/sirupsen/logrus"
	"regexp"
)

var (
	ErrUserNotFound = errors.New("user not found")
	regexAudRepl    = regexp.MustCompile(`\{\{\s*AUDIENCE\s*\}\}`)
)

func GetUserDetails(upn string, params *model.Params) (*model.SysApiUserDetail, error) {
	// Create a Resty Client
	client := resty.New()
	backendBaseUrl := regexAudRepl.ReplaceAllString(_cfg.AdminBackend.BaseUrl, params.Audience)
	log.WithFields(log.Fields{
		"upn":      upn,
		"audience": params.Audience,
	}).Debug("AdminBackend URL: ", backendBaseUrl)
	resp, err := client.R().
		SetHeader("Accept", "application/json").
		SetAuthToken(oauthserver.CreateInternalToken(params)).
		SetResult(&model.SysApiUserDetail{}).
		Get(fmt.Sprintf("%s/sysapi/user/%s/%s", backendBaseUrl, upn, params.Provider))
	if err != nil {
		log.WithFields(log.Fields{
			"upn":      upn,
			"provider": params.Provider,
		}).Error(err)
		return nil, err
	}
	if resp.StatusCode() != 200 {
		log.WithFields(log.Fields{
			"upn":        upn,
			"provider":   params.Provider,
			"statusCode": resp.StatusCode(),
			"fullStatus": resp.Status(),
			"respBody":   string(resp.Body()),
		}).Warn("Unexpected response")
		if resp.StatusCode() == 404 {
			return nil, ErrUserNotFound
		} else {
			return nil, errors.New("unexpected response from admin backend")
		}
	}

	result := resp.Result().(*model.SysApiUserDetail)

	return result, nil
}

func CreateDeviceLogin(upn string, code string, provider string, audience string) error {
	// Create a Resty Client
	client := resty.New()
	backendBaseUrl := regexAudRepl.ReplaceAllString(_cfg.AdminBackend.BaseUrl, audience)
	log.WithFields(log.Fields{
		"upn":      upn,
		"audience": audience,
	}).Debug("AdminBackend URL: ", backendBaseUrl)
	resp, err := client.R().
		SetHeader("Accept", "application/json").
		SetAuthToken(oauthserver.CreateInternalToken(&model.Params{Upn: upn})).
		Post(fmt.Sprintf("%s/sysapi/user/%s/device/%s?provider=%s", backendBaseUrl, upn, code, provider))
	if err != nil {
		log.WithFields(log.Fields{
			"upn":      upn,
			"provider": code,
		}).Error(err)
		return err
	}
	if resp.StatusCode() != 200 {
		log.WithFields(log.Fields{
			"upn":        upn,
			"statusCode": resp.StatusCode(),
			"fullStatus": resp.Status(),
			"respBody":   string(resp.Body()),
		}).Warn("Unexpected response")
		if resp.StatusCode() == 404 {
			return ErrUserNotFound
		} else {
			log.Error("unexpected response from admin backend:" + string(resp.Body()))
			return errors.New("unexpected response from admin backend")
		}
	}

	return nil
}
