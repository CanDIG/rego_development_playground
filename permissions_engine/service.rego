package service

#
# Verifies that a service is who it says it is
#
import data.vault.service_token as service_token
import rego.v1

verified if {
	service_token == input.token
}

minus(service, info) := "opa service is running"
