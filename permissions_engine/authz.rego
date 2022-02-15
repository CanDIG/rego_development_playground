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
    "tokenControlledAccessREMS": {
        "path": ["v1", "data", "ga4ghPassport", "tokenControlledAccessREMS"]
    }
}

# Tokens provided asn env variables

env := opa.runtime().env
root_token := object.get(env, "CLIENT_SECRET_ROOT", "no_root_token")
service_token := object.get(env, "CLIENT_SECRET_SERVICE", "no_service_token")

tokens = {
    root_token : {
        "roles": ["admin"]
    },
    service_token : {
        "roles": ["datasets", "tokenControlledAccessREMS"]
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

identity_rights[right] {             # Right is in the identity_rights set if...
    token := tokens[input.identity]  # Token exists for identity, and...
    role := token.roles[_]           # Token has a role, and...
    right := rights[role]            # Role has rights defined.
}