import json
import os
from authx.auth import get_vault_token_for_service
import sys
import requests


# get the token for the opa store
try:
    with open("/app/permissions_engine/opa_secret.json") as f:
        opa_json = json.load(f)
        opa_token = get_vault_token_for_service("opa")
        headers = {
            "X-Opa": opa_json["opa_secret"],
            "Content-Type": "application/json; charset=utf-8"
        }
        payload = f"{{\"token\": \"{opa_token}\"}}"
        response = requests.put(url=f"{os.getenv('OPA_URL')}/v1/data/store_token", headers=headers, data=payload)
        print(response.text)
except Exception as e:
    print(str(e))
    sys.exit(1)
