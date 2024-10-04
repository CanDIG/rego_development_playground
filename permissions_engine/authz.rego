package system.authz

# this defines authentication to have access to opa at all
# from: https://www.openpolicyagent.org/docs/v0.22.0/security/#token-based-authentication-example

# Reject requests by default
default allow = false

# Site admin should be able to see anything
allow {
    data.permissions.site_admin == true
}

# Any service should be able to verify that a service is who it says it is:
allow {
    input.path == ["v1", "data", "service", "verified"]
    input.method == "POST"
}

# Opa should be able to store its vault token
allow {
    input.path == ["v1", "data", "store_token"]
    input.method == "PUT"
    input.headers["X-Opa"][_] == data.opa_secret
}

# Service-info path for healthcheck
allow {
    input.path == ["v1", "data", "service", "service-info"]
    input.method == "GET"
}

# The authx library uses these paths:
authx_paths = {
    "permissions": ["v1", "data", "permissions"],
    "user_id": ["v1", "data", "idp", "user_key"]
}

# An authorized user has a valid token (and passes in that same token for both bearer and body)
# Authz users can access the authx paths
allow {
    input.path == authx_paths[_]
    input.method == "POST"
    data.permissions.valid_token == true
    input.body.input.token == input.identity
}
