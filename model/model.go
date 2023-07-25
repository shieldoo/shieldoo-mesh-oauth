package model

type SysApiUserDetail struct {
	UPN    string   `json:"upn"`
	Origin string   `json:"origin"`
	Name   string   `json:"name"`
	Roles  []string `json:"roles"`
}

type Params struct {
	Code     string `json:"code,omitempty"`
	Upn      string `json:"upn,omitempty"`
	Name     string `json:"name,omitempty"`
	Audience string `json:"audience,omitempty"`
	Tenant   string `json:"tenant,omitempty"`
	Provider string `json:"provider,omitempty"`
	Redirect string `json:"redirect,omitempty"`
}

type Message struct {
	Message string
}
