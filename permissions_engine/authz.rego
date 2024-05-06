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
    "site_admin": {
        "path": ["v1", "data", "permissions", "site_admin"]
    },
    "user_id": {
        "path": ["v1", "data", "idp", "user_key"]
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
        "roles": ["datasets", "allowed", "site_admin", "user_id", "tokenControlledAccessREMS"]
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

# Any service should be able to verify that a service is who it says it is:
allow {
    input.path == ["v1", "data", "service", "verified"]
    input.method == "POST"
}

# Service-info path for healthcheck
allow {
    input.path == ["v1", "data", "service", "service-info"]
    input.method == "GET"
}
