package system.authz

# this defines authentication to have access to opa at all
# from: https://www.openpolicyagent.org/docs/v0.22.0/security/#token-based-authentication-example

default allow = false               # Reject requests by default.

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

# Site admin should be able to see anything
allow {
    data.permissions.site_admin == true
}

# As long as the user is authorized, should be able to get their own datasets
allow {
    input.path == ["v1", "data", "permissions", "datasets"]
    input.method == "POST"
    data.permissions.valid_token == true
    input.body.input.token == input.identity
}

# As long as the user is authorized, should be able to see if they're allowed to view something
allow {
    input.path == ["v1", "data", "permissions", "allowed"]
    input.method == "POST"
    data.permissions.valid_token == true
    input.body.input.token == input.identity
}
