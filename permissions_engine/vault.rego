package vault

#
# Obtain secrets from Opa's service secret store in Vault
#
import rego.v1

import data.idp.user_key
import data.store_token.token as vault_token

# keys are the IDP keys for verifying JWTs, used by idp.rego and authz.rego
keys := http.send({"method": "get", "url": "VAULT_URL/v1/opa/data", "headers": {"X-Vault-Token": vault_token}}).body.data.keys

# paths are the paths authorized for methods, used by permissions.rego
paths := http.send({"method": "get", "url": "VAULT_URL/v1/opa/paths", "headers": {"X-Vault-Token": vault_token}}).body.data.paths

# service_token gets the token saved for a service, used by service.rego
service_token := http.send({"method": "get", "url": concat("/", ["VAULT_URL/v1", input.service, "token", input.token]), "headers": {"X-Vault-Token": vault_token}}).body.data.token

# site_roles are site-wide authorizations, used by permissions.rego and authz.rego
site_roles := http.send({"method": "get", "url": "VAULT_URL/v1/opa/site_roles", "headers": {"X-Vault-Token": vault_token}}).body.data.site_roles

all_programs := http.send({"method": "get", "url": "VAULT_URL/v1/opa/programs", "headers": {"X-Vault-Token": vault_token}}).body.data.programs

program_auths[p] := program if {
	some p in all_programs
	program := http.send({"method": "get", "url": concat("/", ["VAULT_URL/v1/opa/programs", p]), "headers": {"X-Vault-Token": vault_token}}).body.data[p]
}

# check to see if the user is authorized for any other programs via DACs
user_auth := http.send({"method": "get", "url": concat("/", ["VAULT_URL/v1/opa/users", urlquery.encode(user_key)]), "headers": {"X-Vault-Token": vault_token}, "raise_error": false})

default user_programs := []

user_programs := user_auth.body.data.programs if {
	user_auth.status_code = 200
}

user_frontend_auth := user_auth.status_code == 200