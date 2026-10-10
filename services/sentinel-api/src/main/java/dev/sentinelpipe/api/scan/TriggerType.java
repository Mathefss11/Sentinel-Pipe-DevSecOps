package dev.sentinelpipe.api.scan;

/**
 * What caused a scan request. Informational only in this phase: it is supplied by the
 * caller and is not yet verified against GitHub events or OIDC claims.
 */
public enum TriggerType {

	MANUAL, PUSH, PULL_REQUEST, SCHEDULED

}
