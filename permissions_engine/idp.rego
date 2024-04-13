package idp
# for interacting with the IdP

#
# Store decode and verified token
#

import data.vault.keys as keys

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