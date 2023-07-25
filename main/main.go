package main

import (
	shieldoo_oauth "github.com/shieldoo/shieldoo-mesh-oauth"
)

func main() {
	shieldoo_oauth.Init()
	shieldoo_oauth.Run()
}
