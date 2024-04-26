import json
import os
from authx.auth import set_service_store_secret, add_provider_to_opa, add_program_to_opa
import sys

## Initializes Vault's opa service store with the information for our IDP and the data in site_roles.json, paths.json, programs.json

results = []

try:
    with open('/app/bearer.txt') as f:
        try:
            token = f.read().strip()
            response, status_code = set_service_store_secret("opa", key="data", value=json.dumps({"keys":[]}))
            response = add_provider_to_opa(token, os.getenv("KEYCLOAK_REALM_URL"))
            results.append(response)
        except Exception as e:
            print(str(e))
            sys.exit(1)

    with open('/app/defaults/paths.json') as f:
        data = f.read()
        response, status_code = set_service_store_secret("opa", key="paths", value=data)
        if status_code != 200:
            sys.exit(3)
        results.append(response)

    with open('/app/defaults/site_roles.json') as f:
        data = f.read()
        response, status_code = set_service_store_secret("opa", key="site_roles", value=data)
        if status_code != 200:
            sys.exit(2)
        results.append(response)

    with open('/app/defaults/programs.json') as f:
        programs = json.load(f)
        for program in programs:
            response, status_code = add_program_to_opa(programs[program])
            if status_code != 200:
                sys.exit(2)
            results.append(response)
except Exception as e:
    print(str(e))
    sys.exit(4)

# print(json.dumps(results, indent=4))
sys.exit(0)
