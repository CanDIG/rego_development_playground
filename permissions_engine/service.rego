package service
#
# Verifies that a service is who it says it is
#

import data.vault.service_token as service_token

verified {
    service_token == input.token
}