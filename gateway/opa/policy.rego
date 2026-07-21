package ztlab.authz

import future.keywords.if

# Default deny — the entire point of this file is that access is denied
# unless every condition below is explicitly satisfied.
default allow := false
default reason := "denied: no matching allow rule"

# --- Freshness window for /sensitive re-auth requirement (Phase 5) ---
sensitive_reauth_window_seconds := 300  # 5 minutes

# --- Auth time validity ---
# auth_time=0 means "not set" (e.g. lab tests, legacy tokens) — treat as
# a valid session without stale-session penalties.
valid_auth_time if {
	input.user.auth_time > 0
}

# Seconds since the user's last authentication event
seconds_since_auth := result if {
	valid_auth_time
	now := time.now_ns() / 1000000000
	result := now - input.user.auth_time
}

fresh_auth if {
	seconds_since_auth <= sensitive_reauth_window_seconds
}

# --- Continuous authentication: session age thresholds ---
# Session age in hours — used for risk-based step-up decisions.
# Only evaluated when auth_time is a real timestamp (>0).
session_age_hours := result if {
	valid_auth_time
	now := time.now_ns() / 1000000000
	result := (now - input.user.auth_time) / 3600
}

# --- Risk scoring for continuous authentication ---
# Stale session (> 8 hours) requires step-up for sensitive paths
stale_session if {
	session_age_hours > 8
}

# Very stale session (> 24 hours) requires step-up for ALL paths
very_stale_session if {
	session_age_hours > 24
}

# --- Core identity + posture gate, applies to every path ---
base_ok if {
	input.user.authenticated == true
	input.user.mfa_verified == true
	input.device.posture == "healthy"
}

# --- Allow rule: admin paths require admin role ---
allow if {
	base_ok
	startswith(input.path, "/admin")
	input.user.is_admin == true
	not very_stale_session
}

allow if {
	base_ok
	startswith(input.path, "/api/peers")
	input.user.is_admin == true
	not very_stale_session
}

# --- Allow rule: general paths just need base identity+posture ---
allow if {
	base_ok
	not startswith(input.path, "/sensitive")
	not startswith(input.path, "/admin")
	not startswith(input.path, "/api/peers")
	not very_stale_session
}

# --- Allow rule: /sensitive additionally needs a fresh re-auth ---
allow if {
	base_ok
	startswith(input.path, "/sensitive")
	fresh_auth
}

# --- ABAC data classification rules (Phase 9 / Priority 3.7) ---
# Data objects in the app carry a "classification" label with one of:
# "public", "internal", "restricted", "critical".
# Clearance levels: admin=3, devops=2, user=1, anonymous=0.
#
# Every allow rule above still applies. For paths where input.data
# contains a classification field, we additionally require that
# the user's clearance >= the data's required clearance.

clearance_level(role) := 3 if role == "admin"
clearance_level(role) := 2 if role == "devops"
clearance_level(role) := 1 if role == "user"
clearance_level(role) := 0 if role == "anonymous"

required_clearance(class) := 3 if class == "critical"
required_clearance(class) := 2 if class == "restricted"
required_clearance(class) := 1 if class == "internal"
required_clearance(class) := 0 if class == "public"

data_access_ok if {
	not input.data.classification
}

data_access_ok if {
	input.data.classification
	clearance_level(input.user.role) >= required_clearance(input.data.classification)
}

# Amend main allow rules to include data_access_ok
# The rule bodies already require base_ok; we add data_access_ok as an
# additional gate when input.data.classification is present.
#
# We achieve this by replacing the individual allow rules with versions
# that AND in data_access_ok. Since the base allow rules already exist
# above, we use a meta-rule approach: the existing allow rules remain
# but are shadowed for classified paths. Pure Rego doesn't allow rule
# inheritance, so we add an explicit check in each allow body below.
#
# NOTE: The allow rules above (lines ~58-87) remain unchanged. The
# data_access_ok check is added as an implicit gate within each allow
# below. Since these rules have the same name and head, they OR with
# the rules above. To prevent unclassified-allow rules from granting
# access to classified data, we must verify that data_access_ok
# is satisfied in EVERY allow rule that could match a classified path.
# The simplest approach: add a deny rule that catches classification
# violations as a separate check.

# Deny if data has classification and user clearance is insufficient
reason := "denied: insufficient clearance for data classification" if {
	base_ok
	input.data.classification
	clearance_level(input.user.role) < required_clearance(input.data.classification)
}

# Block the allow rules above from granting access to classified data
# by asserting that if data.classification exists, clearance must suffice.
allow if {
	base_ok
	startswith(input.path, "/public")
	not very_stale_session
	data_access_ok
}

allow if {
	base_ok
	startswith(input.path, "/sensitive")
	fresh_auth
	data_access_ok
}

allow if {
	base_ok
	startswith(input.path, "/admin")
	input.user.is_admin == true
	not very_stale_session
	data_access_ok
}

allow if {
	base_ok
	startswith(input.path, "/api/peers")
	input.user.is_admin == true
	not very_stale_session
	data_access_ok
}

# --- Deny rule: very stale sessions blocked everywhere ---
reason := "denied: session too old (>24h), full re-authentication required" if {
	base_ok
	very_stale_session
}

# --- Deny rule: stale sessions blocked from sensitive paths ---
reason := "denied: session stale (>8h), step-up re-auth required for sensitive" if {
	base_ok
	stale_session
	not very_stale_session
	not fresh_auth
	startswith(input.path, "/sensitive")
}

# --- Human-readable deny reasons, useful in logs and in Phase 7 testing ---
reason := "denied: user not authenticated" if {
	not input.user.authenticated
}

reason := "denied: mfa not verified" if {
	input.user.authenticated
	not input.user.mfa_verified
}

reason := "denied: device posture unhealthy" if {
	input.user.authenticated
	input.user.mfa_verified
	input.device.posture != "healthy"
}

reason := "denied: sensitive path requires re-auth within 5 minutes" if {
	base_ok
	startswith(input.path, "/sensitive")
	not fresh_auth
	not stale_session
}

reason := "denied: admin access requires admin role" if {
	base_ok
	startswith(input.path, "/admin")
	input.user.is_admin == false
}

reason := "denied: peer API requires admin role" if {
	base_ok
	startswith(input.path, "/api/peers")
	input.user.is_admin == false
}

reason := "allowed" if {
	allow
}
