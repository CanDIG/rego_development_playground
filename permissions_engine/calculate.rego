package calculate

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
import data.idp.user_key as user_key

import rego.v1

#
# This user is a site admin if they have the site_admin role
#
import data.vault.site_roles as site_roles

site_admin if {
	user_key in site_roles.admin
}

site_curator if {
	user_key in site_roles.curator
}

#
# what programs are available to this user?
#

import data.vault.all_programs as all_programs
import data.vault.program_auths as program_auths
import data.vault.user_programs as user_programs

# compile list of programs specifically authorized for the user by DACs and within the authorized time period
user_readable_programs[p.program_id] := output if {
	some p in user_programs
	time.parse_ns("2006-01-02", p.start_date) <= time.now_ns()
	time.parse_ns("2006-01-02", p.end_date) >= time.now_ns()
	output := p
}

# compile list of programs that list the user as a team member
team_readable_programs[p] := output if {
	some p in all_programs
	user_key in program_auths[p].team_members
	output := program_auths[p].team_members
}

# user can read programs that are either team-readable or user-readable
readable_programs := object.keys(object.union(team_readable_programs, user_readable_programs))

# user can curate programs that list the user as a program curator
curateable_programs[p] if {
	some p in all_programs
	user_key in program_auths[p].program_curators
}

import data.vault.paths as paths

# debugging
readable_get[p] := output if {
	some p in paths.read.get
	output := regex.match(p, input.body.path)
}

readable_post[p] := output if {
	some p in paths.read.post
	output := regex.match(p, input.body.path)
}

curateable_get[p] := output if {
	some p in paths.curate.get
	output := regex.match(p, input.body.path)
}

curateable_post[p] := output if {
	some p in paths.curate.post
	output := regex.match(p, input.body.path)
}

curateable_delete[p] := output if {
	some p in paths.curate.delete
	output := regex.match(p, input.body.path)
}

# which datasets can this user see for this method, path
default datasets := []

# site admins can see all programs
datasets := all_programs if {
	site_admin
}

# if user is a team_member, they can access programs that allow read access for this method, path
else := readable_programs if {
	input.body.method = "GET"
	regex.match(paths.read.get[_], input.body.path) == true
}

else := readable_programs if {
	input.body.method = "POST"
	regex.match(paths.read.post[_], input.body.path) == true
}

# if user is a site curator, they can access all programs that allow curate access for this method, path
else := all_programs if {
	user_key in site_roles.curator
	input.body.method = "GET"
	regex.match(paths.curate.get[_], input.body.path) == true
}

else := all_programs if {
	user_key in site_roles.curator
	input.body.method = "POST"
	regex.match(paths.curate.post[_], input.body.path) == true
}

else := all_programs if {
	user_key in site_roles.curator
	input.body.method = "DELETE"
	regex.match(paths.curate.delete[_], input.body.path) == true
}

# if user is a program_curator, they can access programs that allow curate access for them for this method, path
else := curateable_programs if {
	input.body.method = "GET"
	regex.match(paths.curate.get[_], input.body.path) == true
}

else := curateable_programs if {
	input.body.method = "POST"
	regex.match(paths.curate.post[_], input.body.path) == true
}

else := curateable_programs if {
	input.body.method = "DELETE"
	regex.match(paths.curate.delete[_], input.body.path) == true
}
