#!/usr/bin/env bash

set -Euo pipefail

OPA_ROOT_TOKEN=$(cat /run/secrets/opa-root-token)
OPA_SERVICE_TOKEN=$(cat /run/secrets/opa-service-token)

if [[ -f "/app/initial_setup" ]]; then
    # set up our default values
    sed -i s/CANDIG_USER_KEY/$CANDIG_USER_KEY/ /app/permissions_engine/idp.rego

    # set up default users in default jsons:
    sed -i s/SITE_ADMIN_USER/$SITE_ADMIN_USER/ /app/defaults/site_roles.json
    sed -i s/USER1/$USER1/ /app/defaults/site_roles.json
    sed -i s/USER2/$USER2/ /app/defaults/site_roles.json
    sed -i s/SITE_ADMIN_USER/$SITE_ADMIN_USER/ /app/defaults/programs.json
    sed -i s/USER1/$USER1/ /app/defaults/programs.json
    sed -i s/USER2/$USER2/ /app/defaults/programs.json

    sed -i s/OPA_SERVICE_TOKEN/$OPA_SERVICE_TOKEN/ /app/permissions_engine/authz.rego
    sed -i s/OPA_ROOT_TOKEN/$OPA_ROOT_TOKEN/ /app/permissions_engine/authz.rego

    # set up vault URL
    sed -i s@VAULT_URL@$VAULT_URL@ /app/permissions_engine/vault.rego

    echo "initializing stores"
    python3 /app/initialize_vault_store.py
    if [[ $? -eq 0 ]]; then
        rm /app/initial_setup
        rm /app/bearer.txt
        echo "setup complete"
    else
        echo "!!!!!! INITIALIZATION FAILED, TRY AGAIN !!!!!!"
    fi
fi


while [ 0 -eq 0 ]
do
  echo "storing vault token"
  python3 get_vault_store_token.py
  if [[ $? -eq 0 ]]; then
      echo "vault token stored"
      sleep 300
  else
      echo "vault token not stored"
      sleep 30
  fi
done
