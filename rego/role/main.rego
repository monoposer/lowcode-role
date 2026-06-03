package role

# input.user.sub, input.user.roles (array)
# input.request.action, input.request.resource.type (+ optional id, owner_id, attrs)

default allow = false

allow {
	role := input.user.roles[_]
	grant := data.role_grants[role]
	perm := grant.permissions[_]
	perm == sprintf("%s:%s", [input.request.resource.type, input.request.action])
}

allow {
	role := input.user.roles[_]
	grant := data.role_grants[role]
	grant.permissions[_] == "*:*"
}
