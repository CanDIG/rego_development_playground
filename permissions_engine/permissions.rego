package permissions
#
# This is the set of policy definitions for the permissions engine.
#

import data.store_token.token as token
#
# Provided:
# input = {
#     'token': user token
#     'method': method requested at data service
#     'path': path to request at data service
#     'program': name of program (optional)
# }
#
import data.idp.valid_token
import data.idp.user_key
import data.idp.site_admin

#
# what programs are available to this user?
#

import future.keywords.in

all_programs = http.send({"method": "get", "url": "VAULT_URL/v1/opa/programs", "headers": {"X-Vault-Token": token}}).body.data.programs
program_auths[p] := program {
    some p in all_programs
    program := http.send({"method": "get", "url": concat("/", ["VAULT_URL/v1/opa/programs", p]) , "headers": {"X-Vault-Token": token}}).body.data[p]
}

readable_programs[p] {
    some p in all_programs
    user_key in program_auths[p].team_members
}

curateable_programs[p] {
    some p in all_programs
    user_key in program_auths[p].program_curators
}

paths = http.send({"method": "get", "url": "VAULT_URL/v1/opa/paths", "headers": {"X-Vault-Token": token}}).body.data.paths

# which datasets can this user see for this method, path
default datasets = []

# site admins can see all programs
datasets := all_programs
{
    site_admin
}

# if user is a team_member, they can access programs that allow read access for this method, path
else := readable_programs
{
    valid_token
    input.body.method = "GET"
    regex.match(paths.read.get[_], input.body.path) == true
}

else := readable_programs
{
    valid_token
    input.body.method = "POST"
    regex.match(paths.read.post[_], input.body.path) == true
}

# if user is a program_curator, they can access programs that allow curate access for this method, path
else := curateable_programs
{
    valid_token
    input.body.method = "GET"
    regex.match(paths.read.get[_], input.body.path) == true
}

else := curateable_programs
{
    valid_token
    input.body.method = "POST"
    regex.match(paths.curate.post[_], input.body.path) == true
}

# convenience path: if a specific program is in the body, allowed = true if that program is in datasets
allowed := true
{
    input.body.program in datasets
}
else := true
{
    site_admin
}

# specifically return the true/false value for the site_admin endpoint
site_admin := site_admin
