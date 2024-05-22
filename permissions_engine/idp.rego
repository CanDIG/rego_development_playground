package idp
# for interacting with the IdP

#
# Store decode and verified token
#

import data.vault.keys as keys
import future.keywords.in

#
# Function to decode and verify if a token is valid against a key
#
decode_verify_token(key, token) := output {
    issuer := key.iss
    cert := key.cert
    aud := key.aud[_]
    output := io.jwt.decode_verify(     # Decode and verify in one-step
        token,
        {                         # With the supplied constraints:
            "cert": cert,
            "iss": issuer,
            "aud": aud
        }
    )
}

#
# If either input.identity or input.token are valid against an issuer, decode and verify
#
decode_verify_token_output[issuer] := output {
    possible_tokens := ["identity", "token"]
    some i
    issuer := keys[i].iss
    output := decode_verify_token(keys[i], input[possible_tokens[_]])
}

#
# The issuer of this token
#
token_issuer := i {
    some i in object.keys(decode_verify_token_output)
    decode_verify_token_output[i][0] == true
}

#
# Check if token is valid by checking whether decoded_verify output exists or not
#
valid_token = true {
    decode_verify_token_output[_][0]
}

#
# The user's key, as determined by this candig instance
#
user_key := decode_verify_token_output[token_issuer][2].CANDIG_USER_KEY

#
# Check trusted_researcher in the token payload
#
trusted_researcher = true {
    decode_verify_token_output[_][2].trusted_researcher == "true"
}

#
# If the token_issuer is the same as the first listed in keys, this is a local token
#
is_local_token = true {
    keys[0].iss == token_issuer
}
