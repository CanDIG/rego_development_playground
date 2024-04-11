package system.authz

# this defines authentication to have access to opa at all
# from: https://www.openpolicyagent.org/docs/v0.22.0/security/#token-based-authentication-example

rights = {
    "admin": {
        "path": "*"
    },
    "datasets": {
        "path": ["v1", "data", "permissions", "datasets"]
    },
    "allowed": {
        "path": ["v1", "data", "permissions", "allowed"]
    },
    "tokenControlledAccessREMS": {
        "path": ["v1", "data", "ga4ghPassport", "tokenControlledAccessREMS"]
    }
}

root_token := "OPA_ROOT_TOKEN"
service_token := "OPA_SERVICE_TOKEN"

tokens = {
    root_token : {
        "roles": ["admin"]
    },
    service_token : {
        "roles": ["datasets", "allowed", "tokenControlledAccessREMS"]
    }
}

default allow = false               # Reject requests by default.

allow {                             # Allow request if...
    some right
    identity_rights[right]          # Rights for identity exist, and...
    right.path == "*"               # Right.path is '*'.
}

allow {                             # Allow request if...
    some right
    identity_rights[right]          # Rights for identity exist, and...
    right.path == input.path        # Right.path matches input.path.
}

x_opa := input.headers["X-Opa"][_]

identity_rights[right] {             # Right is in the identity_rights set if...
    token := tokens[x_opa]  # Token exists for identity, and...
    role := token.roles[_]           # Token has a role, and...
    right := rights[role]            # Role has rights defined.
}

import data.store_token.token as vault_token

# If user is site_admin, allow always
import future.keywords.in

site_roles = http.send({"method": "get", "url": "VAULT_URL/v1/opa/site_roles", "headers": {"X-Vault-Token": vault_token}}).body.data.site_roles
user_key := decode_verify_token_output[_][2].CANDIG_USER_KEY        # get user key from the token payload

allow {
    user_key in site_roles.admin
}

keys = http.send({"method": "get", "url": "VAULT_URL/v1/opa/data", "headers": {"X-Vault-Token": vault_token}}).body.data.keys
decode_verify_token_output[issuer] := output {
    some i
    issuer := keys[i].iss
    cert := keys[i].cert
    output := io.jwt.decode_verify(     # Decode and verify in one-step
        input.identity,
        {                         # With the supplied constraints:
            "cert": cert,
            "iss": issuer,
            "aud": "CLIENT_ID"
        }
    )
}

# Any service should be able to verify that a service is who it says it is:
allow {
    input.path == ["v1", "data", "service", "verified"]
    input.method == "POST"
}