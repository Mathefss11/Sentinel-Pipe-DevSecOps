package system.authz_test

import data.system.authz

test_health_check_allowed if {
	authz.allow with input as {"method": "GET", "path": ["health"]}
}

test_data_query_allowed if {
	authz.allow with input as {"method": "POST", "path": ["v1", "data", "sentinelpipe", "decision"]}
}

test_data_read_allowed if {
	authz.allow with input as {"method": "GET", "path": ["v1", "data"]}
}

test_policy_upload_denied if {
	not authz.allow with input as {"method": "PUT", "path": ["v1", "policies", "malicious"]}
}

test_policy_listing_denied if {
	not authz.allow with input as {"method": "GET", "path": ["v1", "policies"]}
}

test_data_overwrite_denied if {
	not authz.allow with input as {"method": "PUT", "path": ["v1", "data", "system", "authz"]}
}

test_data_patch_denied if {
	not authz.allow with input as {"method": "PATCH", "path": ["v1", "data"]}
}

test_data_delete_denied if {
	not authz.allow with input as {"method": "DELETE", "path": ["v1", "data", "sentinelpipe"]}
}

test_ad_hoc_query_denied if {
	not authz.allow with input as {"method": "POST", "path": ["v1", "query"]}
}

test_missing_input_denied if {
	not authz.allow with input as {}
}
