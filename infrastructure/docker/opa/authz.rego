# Authorization policy for the local development OPA server (--authorization=basic).
#
# Allows health checks and policy decision queries only. Policy and data
# management APIs (PUT/PATCH/DELETE, /v1/policies) are denied so that no
# client can replace policies at runtime. Deny by default.
package system.authz

default allow := false

allow if {
	input.method == "GET"
	input.path == ["health"]
}

allow if {
	input.method in {"GET", "POST"}
	input.path[0] == "v1"
	input.path[1] == "data"
}
