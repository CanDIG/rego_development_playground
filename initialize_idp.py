import json
import os
from authx.auth import add_provider_to_opa, get_user_id
import sys

## Updates Vault's opa service store with the information for our IDP

token = None
try:
    if os.path.isfile('/app/bearer.txt'):
        with open('/app/bearer.txt') as f:
            token = f.read().strip()
    if token is not None:
        response = add_provider_to_opa(token, os.getenv("KEYCLOAK_REALM_URL"))
        os.remove('/app/bearer.txt')
        if get_user_id(None, token=token) is None:
            print("IDP is incorrect: verify that Keycloak is set up and clean/build/compose opa again")
            sys.exit(2)
except Exception as e:
    raise Exception(f"failed to save idp keys: {str(e)} {status_code}")
    sys.exit(1)

sys.exit(0)
