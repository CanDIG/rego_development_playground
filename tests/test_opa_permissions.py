import json
import os
import re
import sys
import pytest
import subprocess
import tempfile
from datetime import date


TODAY = date.today()
THE_PAST = str(date(TODAY.year - 1, TODAY.month, TODAY.day))
THE_FUTURE = str(date(TODAY.year + 1, TODAY.month, TODAY.day))

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
      "curator": [
        "user2@test.ca"
      ],
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


@pytest.fixture
def users():
    return {
        "user1": {
            # user1 is curator for SYNTHETIC-1, SYNTHETIC-3
            # user1 is member of SYNTHETIC-1, SYNTHETIC-3, SYNTHETIC-4
            "user": {
                "user_name": "user1@test.ca"
            },
            "programs": [
                {
                    "program_id": "SYNTHETIC-1",
                    "start_date": THE_PAST,
                    "end_date": THE_FUTURE
                }
            ]
        },
        "user2": {
            # user2 is curator for SYNTHETIC-2
            # user2 is member of SYNTHETIC-2, SYNTHETIC-3
            "user": {
                "user_name": "user2@test.ca"
            },
            "programs": [
                {
                    "program_id": "SYNTHETIC-1",
                    "start_date": THE_PAST,
                    "end_date": THE_FUTURE
                },
                {
                    "program_id": "SYNTHETIC-4",
                    "start_date": THE_PAST,
                    "end_date": THE_FUTURE
                }
            ]
        },
        "user3": {
            # user3 is curator for SYNTHETIC-3
            # user3 is member of SYNTHETIC-3
            "user": {
                "user_name": "user3@test.ca"
            },
            "programs": [
                { # this program is already OVER
                    "program_id": "SYNTHETIC-1",
                    "start_date": THE_PAST,
                    "end_date": THE_PAST
                },
                {
                    "program_id": "SYNTHETIC-4",
                    "start_date": THE_PAST,
                    "end_date": THE_FUTURE
                }
            ]
        },
        "dac_user": {
            "user": {
                "user_name": "dac_user@test.ca"
            },
            "programs": [
                {
                    "program_id": "SYNTHETIC-3",
                    "start_date": THE_PAST,
                    "end_date": THE_FUTURE
                }
            ]
        },
        "user_auth_only": {
            # user_auth_only is authorized for no programs
            "user": {
                "user_name": "user_auth_only@test.ca"
            },
            "programs": []
        },
        "site_admin": {
            "user": {
                "user_name": "site_admin@test.ca"
            },
            "programs": []
        },

    }


def setup_vault(user, site_roles, users, programs):
    vault = {"vault": {}}
    vault["vault"]["program_auths"] = programs
    vault["vault"]["all_programs"] = list(programs.keys())
    vault["vault"]["site_roles"] = site_roles
    user_read_auth = users[user]
    vault["vault"]["user_programs"] = user_read_auth["programs"]
    with open(f"{DEFAULTS_DIR}/paths.json") as f:
        paths = json.load(f)
        vault["vault"]["paths"] = paths["paths"]
    return vault


def evaluate_opa(user, input, key, expected_result, site_roles, users, programs):
    args = [
        "./opa", "eval",
        "--data", "permissions_engine/authz.rego",
        "--data", "permissions_engine/calculate.rego",
        "--data", "permissions_engine/permissions.rego",
    ]
    vault = setup_vault(user, site_roles, users, programs)

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as vault_fp:
        json.dump(vault, vault_fp)
        args.extend(["--data", vault_fp.name])
        vault_fp.close()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as idp_fp:
            idp = {"idp": {
                    "user_key": users[user]["user"]["user_name"],
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
                result =r['result'][0]['expressions'][0]['value']
                print(result)
                if key in result:
                    assert result[key] == expected_result
                else:
                    assert expected_result == False


def get_site_admin_tests():
    return [
        ( # user1 is not a site admin
            "user1",
            False
        ),
        ( # site_admin is a site admin
            "site_admin",
            True
        )
    ]


@pytest.mark.parametrize('user, expected_result', get_site_admin_tests())
def test_site_admin(user, expected_result, site_roles, users, programs):
    evaluate_opa(user, {}, "site_admin", expected_result, site_roles, users, programs)


def get_user_datasets():
    return [
        (  # site admin should be able to read all datasets
            "site_admin",
            {"body": {"path": "/ga4gh/drs/v1/programs/", "method": "GET"}},
            ["SYNTHETIC-1", "SYNTHETIC-2", "SYNTHETIC-3", "SYNTHETIC-4"],
        ),
        (  # user1 can view the datasets it's a member of
            "user1",
            {"body": {"path": "/v3/discovery/programs/", "method": "GET"}},
            ["SYNTHETIC-1", "SYNTHETIC-3", "SYNTHETIC-4"],
        ),
        (  # user3 can view the datasets it's a member of + DAC programs,
            # but SYNTHETIC-1's authorized dates are in the past
            "user3",
            {"body": {"path": "/v3/discovery/programs/", "method": "GET"}},
            ["SYNTHETIC-3", "SYNTHETIC-4"],
        ),
        (
            "dac_user",
            {"body": {"path": "/ga4gh/drs/v1/programs", "method": "GET"}},
            ["SYNTHETIC-3"],
        ),
    ]


@pytest.mark.parametrize('user, input, expected_result', get_user_datasets())
def test_user_datasets(user, input, expected_result, site_roles, users, programs):
    evaluate_opa(user, input, "datasets", expected_result, site_roles, users, programs)


def get_curation_allowed():
    return [
        ( # site admin should be able to curate all datasets
            "site_admin",
            {
                "body": {
                  "path": "/ga4gh/drs/v1/programs/",
                  "method": "POST"
                }
            },
            True
        ),
        ( # user2 can curate the datasets it's not a curator of because they're a site curator
            "user2",
            {
                "body": {
                  "path": "/ga4gh/drs/v1/programs/",
                  "method": "POST",
                  "program": "SYNTHETIC-1"
                }
            },
            True
        ),
        ( # user1 can curate the datasets it's a curator of
            "user1",
            {
                "body": {
                  "path": "/ga4gh/drs/v1/programs/",
                  "method": "POST",
                  "program": "SYNTHETIC-1"
                }
            },
            True
        ),
        ( # user1 can curate the datasets it's a curator of
            "user1",
            {
                "body": {
                  "path": "/ga4gh/drs/v1/programs/",
                  "method": "DELETE",
                  "program": "SYNTHETIC-1"
                }
            },
            True
        ),
        ( # user1 cannot curate the datasets it's not a curator of
            "user1",
            {
                "body": {
                  "path": "/ga4gh/drs/v1/programs/",
                  "method": "POST",
                  "program": "SYNTHETIC-2"
                }
            },
            False
        )
    ]

@pytest.mark.parametrize('user, input, expected_result', get_curation_allowed())
def test_curation_allowed(user, input, expected_result, site_roles, users, programs):
    evaluate_opa(user, input, "allowed", expected_result, site_roles, users, programs)
