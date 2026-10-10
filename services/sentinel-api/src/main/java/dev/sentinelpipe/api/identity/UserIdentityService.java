package dev.sentinelpipe.api.identity;

import dev.sentinelpipe.api.common.Timestamps;
import java.time.Clock;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Lookup and provisioning of user identities.
 *
 * <p>
 * Identities are <b>not</b> created when a user merely authenticates: an identity row is
 * created only when a privileged actor grants a membership (or a platform administrator
 * bootstraps an organization), after that actor has been authorized. Authentication alone
 * never grants access to anything.
 */
@Service
public class UserIdentityService {

	private final UserIdentityRepository identities;

	private final Clock clock;

	UserIdentityService(UserIdentityRepository identities, Clock clock) {
		this.identities = identities;
		this.clock = clock;
	}

	@Transactional(readOnly = true)
	public Optional<UserIdentity> find(AuthenticatedPrincipal principal) {
		return find(principal.issuer(), principal.subject());
	}

	@Transactional(readOnly = true)
	public Optional<UserIdentity> find(String issuer, String subject) {
		return this.identities.findByIssuerAndSubject(issuer, subject);
	}

	@Transactional(readOnly = true)
	public Map<UUID, UserIdentity> findAllById(List<UUID> ids) {
		return this.identities.findAllById(ids)
			.stream()
			.collect(Collectors.toMap(UserIdentity::getId, Function.identity()));
	}

	/**
	 * Returns the identity, creating it if needed, within the caller's transaction. Uses a
	 * single database connection and is safe under concurrent creation of the same
	 * identity (see {@link UserIdentityRepository#insertIfAbsent}).
	 */
	@Transactional
	public UserIdentity findOrCreate(String issuer, String subject) {
		Optional<UserIdentity> existing = this.identities.findByIssuerAndSubject(issuer, subject);
		if (existing.isPresent()) {
			return existing.get();
		}
		// Validates issuer and subject with the same rules as the entity.
		UserIdentity candidate = UserIdentity.create(issuer, subject, Timestamps.now(this.clock));
		this.identities.insertIfAbsent(candidate.getId(), candidate.getIssuer(), candidate.getSubject(),
				candidate.getCreatedAt());
		return this.identities.findByIssuerAndSubject(issuer, subject)
			.orElseThrow(() -> new IllegalStateException("User identity was not persisted"));
	}

}
