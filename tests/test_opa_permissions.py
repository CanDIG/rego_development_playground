import json
import os
import re
import sys
import pytest
import subprocess
import tempfile


# assumes that we are running pytest from the repo directory
REPO_DIR = os.path.abspath(f"{os.path.dirname(os.path.realpath(__file__))}/..")
DEFAULTS_DIR = f"{REPO_DIR}/defaults"
sys.path.insert(0, os.path.abspath(f"{REPO_DIR}"))

@pytest.fixture
def site_roles():
    return {
      "admin": [
        "site_admin@test.ca"
      ],
      "curator": [],
      "local_team": [
        "user1@test.ca"
      ],
      "mohccn_network": [
        "user1@test.ca",
        "user2@test.ca",
        "other1@other.ca"
      ]
    }


@pytest.fixture
def programs():
    return {
      "SYNTHETIC-1": {
        "date_created": "2020-01-01",
        "program_curators": [
          "user1@test.ca"
        ],
        "program_id": "SYNTHETIC-1",
        "team_members": [
          "user1@test.ca"
        ]
      },
      "SYNTHETIC-2": {
        "date_created": "2020-03-01",
        "program_curators": [
          "user2@test.ca"
        ],
        "program_id": "SYNTHETIC-2",
        "team_members": [
          "user2@test.ca"
        ]
      },
      "SYNTHETIC-3": {
        "date_created": "2020-03-01",
        "program_curators": [
          "user1@test.ca",
          "user3@test.ca"
        ],
        "program_id": "SYNTHETIC-3",
        "team_members": [
          "user1@test.ca",
          "user2@test.ca",
          "user3@test.ca"
        ]
      },
      "SYNTHETIC-4": {
        "date_created": "2020-03-01",
        "program_curators": [
          "user4@test.ca"
        ],
        "program_id": "SYNTHETIC-4",
        "team_members": [
          "user1@test.ca",
          "user4@test.ca"
        ]
      }
    }


def setup_vault(user, site_roles, programs):
    vault = {"vault": {}}
    vault["vault"]["program_auths"] = programs
    vault["vault"]["all_programs"] = list(programs.keys())
    vault["vault"]["site_roles"] = site_roles
    with open(f"{DEFAULTS_DIR}/paths.json") as f:
        paths = json.load(f)
        vault["vault"]["paths"] = paths["paths"]
    return vault


def evaluate_opa(user, input, key, expected_result, site_roles, programs):
    args = [
        "./opa", "eval",
        "--data", "permissions_engine/authz.rego",
        "--data", "permissions_engine/permissions.rego",
    ]
    vault = setup_vault(user, site_roles, programs)

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as vault_fp:
        json.dump(vault, vault_fp)
        args.extend(["--data", vault_fp.name])
        vault_fp.close()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as idp_fp:
            idp = {"idp": {
                    "user_key": user,
                    "valid_token": True
                }
            }
            json.dump(idp, idp_fp)
            idp_fp.close()
            args.extend(["--data", idp_fp.name])
            with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as input_fp:
                json.dump(input, input_fp)
                input_fp.close()
                args.extend(["--input", input_fp.name])

                # finally, query arg:
                args.append("data.permissions")
                print(json.dumps(vault))
                print(json.dumps(idp))
                print(json.dumps({"input": input}))
                p = subprocess.run(args, stdout=subprocess.PIPE)
                r =  json.loads(p.stdout)
                print(r)
                result =r['result'][0]['expressions'][0]['value']
                if key in result:
                    assert result[key] == expected_result
                else:
                    assert expected_result == False


def get_site_admin_tests():
    return [
        ( # user1 is not a site admin
            "user1@test.ca",
            False
        ),
        ( # site_admin is a site admin
            "site_admin@test.ca",
            True
        )
    ]


@pytest.mark.parametrize('user, expected_result', get_site_admin_tests())
def test_site_admin(user, expected_result, site_roles, programs):
    evaluate_opa(user, {}, "site_admin", expected_result, site_roles, programs)


def get_user_datasets():
    return [
        ( # site admin should be able to read all datasets
            "site_admin@test.ca",
            {
                "body": {
                  "path": "/ga4gh/drs/v1/cohorts/",
                  "method": "GET"
                }
            },
            ["SYNTHETIC-1", "SYNTHETIC-2", "SYNTHETIC-3", "SYNTHETIC-4"]
        ),
        ( # user1 can view the datasets it's a member of
            "user1@test.ca",
            {
                "body": {
                  "path": "/v2/discovery/programs/",
                  "method": "GET"
                }
            },
            ["SYNTHETIC-1", "SYNTHETIC-3", "SYNTHETIC-4"]
        )
    ]


@pytest.mark.parametrize('user, input, expected_result', get_user_datasets())
def test_user_datasets(user, input, expected_result, site_roles, programs):
    evaluate_opa(user, input, "datasets", expected_result, site_roles, programs)


def get_curation_allowed():
    return [
        ( # site admin should be able to curate all datasets
            "site_admin@test.ca",
            {
                "body": {
                  "path": "/ga4gh/drs/v1/cohorts/",
                  "method": "POST"
                }
            },
            True
        ),
        ( # user1 can curate the datasets it's a curator of
            "user1@test.ca",
            {
                "body": {
                  "path": "/ga4gh/drs/v1/cohorts/",
                  "method": "POST",
                  "program": "SYNTHETIC-1"
                }
            },
            True
        ),
        ( # user1 cannot curate the datasets it's not a curator of
            "user1@test.ca",
            {
                "body": {
                  "path": "/ga4gh/drs/v1/cohorts/",
                  "method": "POST",
                  "program": "SYNTHETIC-2"
                }
            },
            False
        )
    ]

@pytest.mark.parametrize('user, input, expected_result', get_curation_allowed())
def test_curation_allowed(user, input, expected_result, site_roles, programs):
    evaluate_opa(user, input, "allowed", expected_result, site_roles, programs)
