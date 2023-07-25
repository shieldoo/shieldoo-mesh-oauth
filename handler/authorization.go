package handler

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/shieldoo/shieldoo-mesh-oauth/adminbackend"
	"github.com/shieldoo/shieldoo-mesh-oauth/model"
	"github.com/shieldoo/shieldoo-mesh-oauth/utils"

	log "github.com/sirupsen/logrus"
)

func HandleAuthorization(w http.ResponseWriter, upn string, params *model.Params) (*model.SysApiUserDetail, error) {
	staticAudience := utils.FindStaticAudience(*_cfg, params.Audience)
	if staticAudience != nil && !staticAudience.Authorize {
		log.WithFields(log.Fields{
			"audience": params.Audience,
		}).Debug("Skipping authorization for audience")
		return nil, nil
	}
	details, err := adminbackend.GetUserDetails(upn, params)
	if err != nil {
		if err == adminbackend.ErrUserNotFound {
			utils.GeneralResponseTemplate(w, fmt.Sprintf("User: %s is not member in the organisation %s.", upn,
				strings.ToUpper(params.Audience)), http.StatusNotFound)
			log.Warn(err)
		} else {
			utils.GeneralResponseTemplate(w, "Error when processing request.", http.StatusInternalServerError)
			log.Error(err)
		}
		return nil, err
	}
	return details, nil
}
