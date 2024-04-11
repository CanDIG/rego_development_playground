package idp
# for interacting with the IdP

#
# Store decode and verified token
#

import data.store_token.token as token
keys = http.send({"method": "get", "url": "VAULT_URL/v1/opa/data", "headers": {"X-Vault-Token": token}}).body.data.keys

decode_verify_token_output[issuer] := output {
    some i
    issuer := keys[i].iss
    cert := keys[i].cert
    output := io.jwt.decode_verify(     # Decode and verify in one-step
        input.token,
        {                         # With the supplied constraints:
            "cert": cert,
            "iss": issuer,
            "aud": "CLIENT_ID"
        }
    )
}

#
# Check if token is valid by checking whether decoded_verify output exists or not
#
valid_token = true {
    decode_verify_token_output[_][0]
}

user_key := decode_verify_token_output[_][2].CANDIG_USER_KEY        # get user key from the token payload

#
# Check trusted_researcher in the token payload
#
trusted_researcher = true {
    decode_verify_token_output[_][2].trusted_researcher == "true"
}

#
# This user is a site admin if they have the site_admin role
#
import future.keywords.in

site_roles = http.send({"method": "get", "url": "VAULT_URL/v1/opa/site_roles", "headers": {"X-Vault-Token": token}}).body.data.site_roles
site_admin = true {
    user_key in site_roles.admin
}
