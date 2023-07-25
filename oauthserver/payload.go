package oauthserver

import (
	"errors"
	"github.com/golang-jwt/jwt/v4"
	"time"

	"github.com/google/uuid"
	"github.com/shieldoo/shieldoo-mesh-oauth/model"
)

// define roles in system
const (
	RoleSystem        = "SYSTEM"
	RoleAdministrator = "ADMINISTRATOR"
	RoleUser          = "USER"
)

type Payload struct {
	Issuer   string           `json:"iss"`
	Id       uuid.UUID        `json:"jti"`
	Upn      string           `json:"upn"`
	Aud      string           `json:"aud"`
	Name     string           `json:"name,omitempty"`
	Provider string           `json:"provider,omitempty"`
	Tenant   string           `json:"tenant,omitempty"`
	IssueAt  *jwt.NumericDate `json:"iat,omitempty"`
	ExpiryAt *jwt.NumericDate `json:"exp,omitempty"`
	Roles    []string         `json:"roles,omitempty"`
}

var (
	ErrInvalidToken = errors.New("token is invalid")
	ErrExpiredToken = errors.New("token has expired")
)

func NewPayload(params *model.Params, duration time.Duration, details *model.SysApiUserDetail) (*Payload, error) {
	tokenID, err := uuid.NewRandom()
	if err != nil {
		return nil, err
	}

	var payload = &Payload{
		Id:       tokenID,
		Upn:      params.Upn,
		Name:     params.Name,
		Aud:      params.Audience,
		Provider: params.Provider,
		Tenant:   params.Tenant,
		Issuer:   _cfg.OAuthServer.Issuer,
		ExpiryAt: jwt.NewNumericDate(time.Now().Add(duration)),
		IssueAt:  jwt.NewNumericDate(time.Now()),
	}
	if details != nil {
		payload.Roles = details.Roles
	}
	return payload, nil
}

func (payload *Payload) Valid() error {
	if time.Now().After(payload.ExpiryAt.Time) {
		return ErrExpiredToken
	}
	return nil
}
