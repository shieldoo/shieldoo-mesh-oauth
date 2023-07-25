# Shieldoo Oauth Proxy

[![Build](https://github.com/shieldoo/shieldoo-mesh-oauth/actions/workflows/build-release.yml/badge.svg)](https://github.com/shieldoo/shieldoo-mesh-oauth/actions/workflows/build-release.yml) 
[![Release](https://img.shields.io/github/v/release/shieldoo/shieldoo-mesh-oauth?logo=GitHub&style=flat-square)](https://github.com/shieldoo/shieldoo-mesh-oauth/releases/latest) 
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=shieldoo_shieldoo-mesh-oauth&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=shieldoo_shieldoo-mesh-oauth) 
[![Bugs](https://sonarcloud.io/api/project_badges/measure?project=shieldoo_shieldoo-mesh-oauth&metric=bugs)](https://sonarcloud.io/summary/new_code?id=shieldoo_shieldoo-mesh-oauth) 
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=shieldoo_shieldoo-mesh-oauth&metric=security_rating)](https://sonarcloud.io/summary/new_code?id=shieldoo_shieldoo-mesh-oauth)

## What is Shieldoo Oauth Proxy?

The Shieldoo Oauth Proxy is a crucial component of the Shieldoo project, designed to manage the OAuth authentication process. This process involves the integration of external providers such as Google and Azure Active Directory (AAD) authentication services, creation of JSON Web Tokens (JWT), and redirecting to a specified audience. Furthermore, the proxy handles user verification in the target shieldoo-mesh-admin service, checking if the user exists and their associated roles.

## Architecture

The architecture of the Shieldoo Oauth Proxy is centered on the facilitation of robust authentication and authorization operations.

Firstly, the proxy connects to external OAuth providers, namely Google and Azure AAD, to authenticate the user. During this process, a JWT token is created for the authenticated user, encapsulating key user details such as their ID, email, tenant, roles, and the provider used for the authentication.

The generated token is then sent back to the client as a redirect to the provided audience. The audience, in this context, denotes the scope of the authenticated user and can be considered as the party intended to receive the JWT. 

The proxy also handles user authorization by interacting with the shieldoo-mesh-admin service. It verifies if the authenticated user exists within this service and retrieves their assigned roles, thereby ensuring proper access control.

The source code of the Oauth Proxy is organized in a way that promotes customization and extensibility. Particularly, the `./main` directory contains the implementation of the launch process which can be easily customized to suit specific requirements.

## Build

The Shieldoo Oauth Proxy is developed using Go and can be built locally using Go's build command. It can also be packaged into a Docker image for easier distribution and deployment.

```bash
# Build for local use
go build -o out/shdoauth ./main

# Build for docker
docker build -t ghcr.io/shieldoo/shieldoo-mesh-oauth:latest .
```

## Expected URL parameters

There are two main URL parameters that the Oauth Proxy expects, namely `audience` and `code`.

The `audience` parameter specifies the scope of the incoming user, and it is a mandatory field. 

On the other hand, the `code` parameter is optional and serves as the pairing code when calling the Oauth Proxy. If it's filled, device login will be used, eliminating the need for further redirects after a successful login.

|   Name   |                                                      Description                                                       |      Validation pattern       | Mandatory |                 Example                  |
|:--------:|:----------------------------------------------------------------------------------------------------------------------:|:-----------------------------:|:---------:|:----------------------------------------:|
| audience |                                Scope of the incoming user, see chapter #StaticAudience                                 | `^[a-zA-Z][a-zA-Z0-9]{2,63}$` |    yes    |                  billa                   |
|   code   | Pairing code when calling Oauth Proxy, if filled, device login will be used (no other redirect after successful login) |    `^[a-zA-Z0-9]{32,64}$`     |    no     | 8789798454654587879878978954654654578798 |

## Supported endpoints

The Oauth Proxy exposes several endpoints that facilitate the OAuth process, handle user redirections, and provide information about the JWTs being used. These endpoints include the base login page, authorization form, provider-specific callback URLs, and endpoints for retrieving JWT key set information (JWKS) and OpenID configuration.

|    Relative path    |                    Description                     | HTTP Method |
|:-------------------:|:--------------------------------------------------:|:-----------:| 
|       /        |                  Base login page                   |     GET     |
|     /authorize      |            Form when selecting provider            |    POST     |
| /callback/microsoft | Redirect URL when receiving response from provider |    POST     |
|  /callback/google   | Redirect URL when receiving response from provider |    POST     |
|  /oauth2/v1/certs   |           GET JWKS info about used keys            |     GET     |
|  /.well-known/openid-configuration   |   OpenId compatible endpoint about configuration   |     GET     |

# JWT

JWTs are a key part of the Oauth Proxy, providing a secure way of transmitting information between parties. Each JWT consists of several fields encapsulating details about the token and authenticated user.

## Configuration

For RSA256 JWT generation, an RSA keypair is required. This can be generated using either OpenSSL or ssh-keygen. 

Once the keypair is generated, it can be used to create a Kubernetes secret that can be automatically mounted to the running pod during Helm deployment.

The Oauth Proxy also supports OpenID Connect and provides a configuration endpoint that returns essential OpenID configuration details.

## JWKS URI

The JWKS URI endpoint allows clients to retrieve public key details to facilitate the validation of JWTs. It returns a set of keys containing key use, key ID, algorithm, and other RSA key-specific information.

## JWT Token Field

|   Name   |                       Description                        
|:--------:|:--------------------------------------------------------:|
|   jti    |                           UUID                           | 
|   iss    |                          Issuer                          | 
|   upn    |                      verified email                      | 
|   aud    |                    verified audience                     | 
| provider | provider used, current supported is google and microsoft | 
|  tenant  |                 tenant if any, optional                  | 
|   iat    |                      JWT issued at                       | 
|   exp    |                    JWT will expire at                    | 
|  roles   |                   list of found roles                    | 

### Example JWT header

```json
{
  "alg": "RS256",
  "kid": "2022030801",
  "typ": "JWT"
}
```

### Example JWT payload data

```json
{
  "iss": "https://login.shieldoo.dev",
  "jti": "1de17e17-a580-4420-8603-a9c2e04a039b",
  "upn": "someone@cloudfield.cz",
  "aud": "register",
  "name": "Someone",
  "provider": "microsoft",
  "tenant": "269a1b55-b8e0-4721-9d49-ae9f28544118",
  "iat": 1649075301,
  "exp": 1649161701,
  "roles": [
    "USER"
  ]
}
```

## Configuration

### RSA keypair for RSA256 JWT generation
Using openssl (verified):
```bash
openssl genrsa -out keypair.pem 2048
openssl rsa -in keypair.pem -pubout -out app.rsa.pub  
openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in keypair.pem -out app.rsa
```

or using ssh-keygen:

```bash
ssh-keygen -t rsa -b 4096 -m PEM -f app.rsa
# Don't add passphrase
openssl rsa -in app.rsa -pubout -outform PEM -out app.rsa.pub
```

#### Create secret from key pair
When created secret  name `nebula-oauth-jwks`, the Helm deployment will mount it to running pod automatically> 
```bash
kubectl create secret generic nebula-oauth-jwks \
--from-file=app.rsa=./jwks/app.rsa \
--from-file=app.rsa.pub=./jwks/app.rsa.pub \
-n shd-oauth
```

## OpenId compatible configuration page
Visiting page `/.well-known/openid-configuration` the OpenId configuration will be shown e.g.:
```json
{
"issuer": "https://www.shieldoo.dev",
"authorization_endpoint": "",
"jwks_uri": "https://www.shieldoo.dev/oauth2/v1/certs"
}
```

## JWKS URI

Oauth server provides information about used JWK URL: `/oauth2/v1/certs`, method GET

Example response:

```json
{
 "keys": [
  {
   "alg": "RS256",
   "e": "AQAB",
   "kid": "mykey",
   "kty": "RSA",
   "n": "rI27gzGj7Zs0gsYut7dE3bWKjkoAM08QyfGWG6GgnZ8BhfYNaWU5dovSPParFgVdImYigfrsE44GvWfbd8PBMenThviXvsncJUVkT9PEAAVpMlmmUtBgr8UM51c4oOOZpntFychAJ3AUGmtQ-vYRoI5j0eShp-EPnkZm8aqTNs8p3BQAsV9c6DCkQK2WTlGvkbwl1nZxcxRjnIu-gDkIlAscwVGM9pkVMXERNNSUesSsL_OAMvhHKoZ__LngGJlhW3nxn7rEO1uFwBUUN19eFgSVzLiwd0eurpKresxM95cTRgL9m930xvVwiJbNDPMJ5ubef87RqqV-LddyeMqoXQ",
   "use": "sig"
  }
 ]
}
```
