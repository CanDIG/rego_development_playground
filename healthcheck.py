import os
import sys
import requests

opa_url = os.environ.get('OPA_URL')


def perform_healthcheck():
    try:
        body = {
            "input": {
                "service": "opa",
                "token": "token" # this isn't important; even if it's wrong, it returns 200
            }
        }
        response = requests.post(f"{opa_url}/v1/data/service/verified", json=body)
        response.raise_for_status()
        print("Health check passed!")
        return True
    except requests.exceptions.RequestException as e:
        print(f"Health check failed: {e}")
        return False


if __name__ == "__main__":
    health_status = perform_healthcheck()
    if not health_status:
        sys.exit(1)
