package vault
#
# Obtain secrets from Opa's service secret store in Vault
#

import future.keywords.in
import data.store_token.token as vault_token
import data.idp.user_key

# keys are the IDP keys for verifying JWTs, used by idp.rego and authz.rego
keys = http.send({"method": "get", "url": "VAULT_URL/v1/opa/data", "headers": {"X-Vault-Token": vault_token}}).body.data.keys

# paths are the paths authorized for methods, used by permissions.rego
paths = http.send({"method": "get", "url": "VAULT_URL/v1/opa/paths", "headers": {"X-Vault-Token": vault_token}}).body.data.paths

# service_token gets the token saved for a service, used by service.rego
service_token = http.send({"method": "get", "url": concat("/", ["VAULT_URL/v1", input.service, "token", input.token]), "headers": {"X-Vault-Token": vault_token}}).body.data.token

# site_roles are site-wide authorizations, used by permissions.rego and authz.rego
site_roles = http.send({"method": "get", "url": "VAULT_URL/v1/opa/site_roles", "headers": {"X-Vault-Token": vault_token}}).body.data.site_roles

all_programs = http.send({"method": "get", "url": "VAULT_URL/v1/opa/programs", "headers": {"X-Vault-Token": vault_token}}).body.data.programs
program_auths[p] := program {
    some p in all_programs
    program := http.send({"method": "get", "url": concat("/", ["VAULT_URL/v1/opa/programs", p]) , "headers": {"X-Vault-Token": vault_token}}).body.data[p]
}