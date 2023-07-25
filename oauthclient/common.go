package oauthclient

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/shieldoo/shieldoo-mesh-oauth/model"
	"github.com/shieldoo/shieldoo-mesh-oauth/utils"
	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
)

var _cfg *utils.Config

func Init(cfg *utils.Config) {
	_cfg = cfg
	InitMicrosoft(cfg)
	InitGoogle(cfg)
	var err error
	if err != nil {
		log.Panic("Unable initialize OauthClient: ", err)
		os.Exit(1000)
	}
}

type Jwks struct {
	Keys []JSONWebKeys `json:"keys"`
}

type JSONWebKeys struct {
	Kty string   `json:"kty"`
	Kid string   `json:"kid"`
	Use string   `json:"use"`
	N   string   `json:"n"`
	E   string   `json:"e"`
	X5c []string `json:"x5c"`
}

func exchangeCode(code string, oauthConfig *oauth2.Config) (*oauth2.Token, error) {
	token, err := oauthConfig.Exchange(context.Background(), code)
	if err != nil {
		log.Error("code exchange failed: ", err.Error())
		return nil, err
	}
	return token, nil
}

func extractIdToken(tokenResponse *oauth2.Token) (string, error) {
	idToken, ok := tokenResponse.Extra("id_token").(string)
	if !ok {
		log.Error("no id_token field in oauth2 token")
		return "", fmt.Errorf("no id_token field in oauth2 token")
	}

	return idToken, nil
}

func decodeParams(state string) (*model.Params, error) {
	var params model.Params
	err := json.Unmarshal([]byte(state), &params)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	return &params, nil
}
