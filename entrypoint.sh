#!/usr/bin/env bash

set -Euo pipefail


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

    token=$(dd if=/dev/urandom bs=1 count=16 2>/dev/null | base64 | tr -d '\n\r+' | sed s/[^A-Za-z0-9]//g)
    echo { \"opa_secret\": \"$token\" } > /app/permissions_engine/opa_secret.json
    # set up vault URL
    sed -i s@VAULT_URL@$VAULT_URL@ /app/permissions_engine/vault.rego

    echo "initializing stores"
    python3 /app/initialize_vault_store.py
    if [[ $? -eq 0 ]]; then
        rm /app/initial_setup
        echo "setup complete"
    else
        echo "!!!!!! INITIALIZATION FAILED, TRY AGAIN !!!!!!"
    fi
fi

# make sure that our idp is still set correctly (maybe keycloak was reinitialized)
python3 get_vault_store_token.py
python3 /app/initialize_idp.py

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
