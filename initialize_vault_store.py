import json
import os
from authx.auth import get_service_store_secret, set_service_store_secret, add_provider_to_opa, add_program_to_opa, list_programs_in_opa
import sys

## Initializes Vault's opa service store with the information for our IDP and the data in site_roles.json, paths.json, programs.json

results = []

try:
    with open('/app/bearer.txt') as f:
        try:
            token = f.read().strip()
            response = add_provider_to_opa(token, os.getenv("KEYCLOAK_REALM_URL"))
            results.append(response)
        except Exception as e:
            print(str(e))
            sys.exit(1)

    response, status_code = get_service_store_secret("opa", key="paths")
    if status_code != 200:
        with open('/app/defaults/paths.json') as f:
            data = f.read()
            response, status_code = set_service_store_secret("opa", key="paths", value=data)
            if status_code != 200:
                sys.exit(3)
            results.append(response)

    response, status_code = get_service_store_secret("opa", key="site_roles")
    if status_code != 200:
        with open('/app/defaults/site_roles.json') as f:
            data = f.read()
            response, status_code = set_service_store_secret("opa", key="site_roles", value=data)
            if status_code != 200:
                sys.exit(2)
            results.append(response)

    current_programs, status_code = list_programs_in_opa()
    if status_code != 200:
        current_programs = []
    with open('/app/defaults/programs.json') as f:
        programs = json.load(f)
        for program in programs:
            if programs[program] not in current_programs:
                response, status_code = add_program_to_opa(programs[program])
                if status_code != 200:
                    sys.exit(2)
                results.append(response)
except Exception as e:
    print(str(e))
    sys.exit(4)

# initialize pending users
response, status_code = get_service_store_secret("opa", key="pending_users")
if status_code == 404:
    response, status_code = set_service_store_secret("opa", key="pending_users", value=json.dumps({"pending_users": {}}))
    if status_code != 200:
        sys.exit(2)

# print(json.dumps(results, indent=4))
sys.exit(0)
