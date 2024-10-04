package permissions
import future.keywords.in

#
# Values that are used by authx
#
valid_token := true {
    data.idp.valid_token
}
else := false

site_admin := data.calculate.site_admin {
    valid_token
}

site_curator := data.calculate.site_curator {
    valid_token
}

datasets := data.calculate.datasets {
    valid_token
}
else := []


# true if the path and method in the input match a readable combo in paths.json
readable_method_path := true {
    input.body.method = "GET"
    data.calculate.readable_get[_]
}
else := true {
    input.body.method = "POST"
    data.calculate.readable_post[_]
}
else := true {
    input.body.method = "DELETE"
    data.calculate.curateable_delete[_]
}
else := false


# true if the path and method in the input match a curateable combo in paths.json
curateable_method_path := true {
    input.body.method = "GET"
    data.calculate.curateable_get[_]
}
else := true {
    input.body.method = "POST"
    data.calculate.curateable_post[_]
}
else := true {
    input.body.method = "DELETE"
    data.calculate.curateable_delete[_]
}
else := false


# if a specific program is in the body, allowed = true if that program is in datasets
# or if the user is a site admin
# or if the user is a site curator and wants to curate something
allowed := true
{
    input.body.program in datasets
}
else := true
{
    site_admin
}
else := true
{
    site_curator
    curateable_method_path
}


#
# User information, for decision log
#

# information from the jwt
user_key := data.idp.user_key
issuer := data.idp.user_info.iss

#
# Debugging information for decision log
#

user_is_site_admin := true {
    user_key in data.vault.site_roles.admin
}
else := false

user_is_site_curator := true {
    user_key in data.vault.site_roles.curator
}
else := false

# programs the user is listed as a team member for
team_member_programs := object.keys(data.calculate.team_readable_programs)

# programs the user is approved by dac for
dac_programs := object.keys(data.vault.user_programs)

# programs the user is listed as a program curator for
curator_programs := data.calculate.curateable_programs
