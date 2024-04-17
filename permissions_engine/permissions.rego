package permissions
#
# This is the set of policy definitions for the permissions engine.
#

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

#
# what programs are available to this user?
#

import future.keywords.in

import data.vault.all_programs as all_programs
import data.vault.program_auths as program_auths

readable_programs[p] {
    some p in all_programs
    user_key in program_auths[p].team_members
}

curateable_programs[p] {
    some p in all_programs
    user_key in program_auths[p].program_curators
}

import data.vault.paths as paths

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
    regex.match(paths.curate.get[_], input.body.path) == true
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

#
# This user is a site admin if they have the site_admin role
#
import data.vault.site_roles as site_roles
site_admin = true {
    user_key in site_roles.admin
}