package idp

# for interacting with the IdP

#
# Store decode and verified token
#

import data.vault.keys as keys

import rego.v1

#
# Function to decode and verify if a token is valid against a key
#
decode_verify_token(key, token) := output if {
	issuer := key.iss
	cert := key.cert
	aud := key.aud[_]
	output := io.jwt.decode_verify(
		token, # Decode and verify in one-step
		{
			"cert": cert, # With the supplied constraints:
			"iss": issuer,
			"aud": aud,
		},
	)
}

decode_token(token) := output if {
	output := io.jwt.decode(token)
}

decoded_output := output if {
	possible_tokens := ["identity", "token"]
	output := decode_token(input[possible_tokens[_]])
}

user_info := decoded_output[1]

#
# The user's key, as determined by this candig instance
#
user_key := user_info.CANDIG_USER_KEY

#
# If either input.identity or input.token are valid against an issuer, decode and verify
#
decode_verify_token_output[issuer] := output if {
	possible_tokens := ["identity", "token"]
	some i
	issuer := keys[i].iss
	output := decode_verify_token(keys[i], input[possible_tokens[_]])
}

#
# The issuer of this token
#
token_issuer := i if {
	some i in object.keys(decode_verify_token_output)
	decode_verify_token_output[i][0] == true
}

#
# Check if token is valid by checking whether decoded_verify output exists or not
#
valid_token if {
	decode_verify_token_output[_][0]
}

#
# Check trusted_researcher in the token payload
#
trusted_researcher if {
	decode_verify_token_output[_][2].trusted_researcher == "true"
}

#
# If the token_issuer is the same as the first listed in keys, this is a local token
#
is_local_token if {
	keys[0].iss == token_issuer
}
