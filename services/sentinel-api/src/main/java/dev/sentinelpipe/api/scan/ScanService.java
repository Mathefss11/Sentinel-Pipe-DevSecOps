package dev.sentinelpipe.api.scan;

import dev.sentinelpipe.api.common.ConstraintViolations;
import dev.sentinelpipe.api.common.DomainValidationException;
import dev.sentinelpipe.api.common.GitBranchNames;
import dev.sentinelpipe.api.common.IdempotencyKeyReuseException;
import dev.sentinelpipe.api.common.ResourceNotFoundException;
import dev.sentinelpipe.api.common.Timestamps;
import dev.sentinelpipe.api.project.ProjectService;
import dev.sentinelpipe.api.scanjob.ScanJob;
import dev.sentinelpipe.api.scanjob.ScanJobRepository;
import java.time.Clock;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Creation and retrieval of scans.
 *
 * <p>
 * <b>Idempotency.</b> Scan requests may carry an {@code Idempotency-Key}, scoped to the
 * project. The key and a SHA-256 fingerprint of the normalized request are stored on the
 * scan, protected by the {@code uq_scans_project_idempotency_key} unique constraint:
 * <ul>
 * <li>same key, same request: the existing scan is returned (replay);</li>
 * <li>same key, different request: {@link IdempotencyKeyReuseException};</li>
 * <li>concurrent first requests with the same key: exactly one insert succeeds; the
 * others hit the unique constraint, and are then resolved as a replay or a conflict in a
 * new transaction.</li>
 * </ul>
 * Correctness relies on the database constraint, not on in-memory locks, so it holds
 * across application instances. Keys do not expire yet.
 */
@Service
public class ScanService {

	public static final int IDEMPOTENCY_KEY_MAX_LENGTH = 128;

	public static final String IDEMPOTENCY_KEY_REGEX = "^[A-Za-z0-9._:-]{1,128}$";

	private static final Pattern IDEMPOTENCY_KEY = Pattern.compile(IDEMPOTENCY_KEY_REGEX);

	private static final Sort LIST_ORDER = Sort.by(Sort.Order.desc("requestedAt"), Sort.Order.desc("id"));

	/** Outcome of a scan request; {@code replayed} is true for an idempotent replay. */
	public record ScanRequestOutcome(ScanDetails details, boolean replayed) {
	}

	private final ScanRepository scans;

	private final ScanJobRepository scanJobs;

	private final ProjectService projectService;

	private final TransactionTemplate writeTransaction;

	private final TransactionTemplate readTransaction;

	private final Clock clock;

	ScanService(ScanRepository scans, ScanJobRepository scanJobs, ProjectService projectService,
			PlatformTransactionManager transactionManager, Clock clock) {
		this.scans = scans;
		this.scanJobs = scanJobs;
		this.projectService = projectService;
		this.writeTransaction = new TransactionTemplate(transactionManager);
		this.readTransaction = new TransactionTemplate(transactionManager);
		this.readTransaction.setReadOnly(true);
		this.clock = clock;
	}

	/**
	 * Queues a new scan, or replays the scan previously created with the same
	 * idempotency key. This method deliberately manages its own transactions: a unique
	 * constraint violation aborts the PostgreSQL transaction, so the replay lookup must
	 * run in a new one.
	 * @param idempotencyKey optional; {@code null} always creates a new scan
	 */
	public ScanRequestOutcome requestScan(UUID projectId, String commitSha, String branch, TriggerType triggerType,
			String idempotencyKey) {
		Objects.requireNonNull(projectId, "projectId");
		String normalizedSha = CommitShas.normalize(commitSha);
		String validatedBranch = GitBranchNames.require("branch", branch);
		if (triggerType == null) {
			throw new DomainValidationException("triggerType", "must not be null");
		}
		String fingerprint = null;
		if (idempotencyKey != null) {
			requireValidIdempotencyKey(idempotencyKey);
			fingerprint = ScanRequestFingerprint.of(normalizedSha, validatedBranch, triggerType);
			Optional<ScanRequestOutcome> replay = findReplay(projectId, idempotencyKey, fingerprint);
			if (replay.isPresent()) {
				return replay.get();
			}
		}
		String requestFingerprint = fingerprint;
		try {
			return this.writeTransaction.execute((status) -> {
				this.projectService.requireAcceptingScans(projectId);
				Scan scan = Scan.request(projectId, normalizedSha, validatedBranch, triggerType, idempotencyKey,
						requestFingerprint, Timestamps.now(this.clock));
				this.scans.saveAndFlush(scan);
				return new ScanRequestOutcome(new ScanDetails(scan, List.of()), false);
			});
		}
		catch (DataIntegrityViolationException ex) {
			if (idempotencyKey != null && ConstraintViolations.isViolationOf(ex, "uq_scans_project_idempotency_key")) {
				return findReplay(projectId, idempotencyKey, requestFingerprint).orElseThrow(() -> ex);
			}
			throw ex;
		}
	}

	public ScanDetails get(UUID scanId) {
		return this.readTransaction.execute((status) -> {
			Scan scan = this.scans.findById(scanId).orElseThrow(() -> new ResourceNotFoundException("Scan", scanId));
			return new ScanDetails(scan, this.scanJobs.findByScanIdOrderByScannerTypeAsc(scanId));
		});
	}

	/** Newest first. Jobs for the whole page are loaded with a single query. */
	public Page<ScanDetails> listByProject(UUID projectId, int page, int size) {
		return this.readTransaction.execute((status) -> {
			this.projectService.requireExists(projectId);
			Page<Scan> scans = this.scans.findByProjectId(projectId, PageRequest.of(page, size, LIST_ORDER));
			List<UUID> scanIds = scans.getContent().stream().map(Scan::getId).toList();
			Map<UUID, List<ScanJob>> jobsByScan = scanIds.isEmpty() ? Map.of()
					: this.scanJobs.findByScanIdIn(scanIds)
						.stream()
						.sorted(Comparator.comparing((ScanJob job) -> job.getScannerType().name()))
						.collect(Collectors.groupingBy(ScanJob::getScanId));
			return scans.map((scan) -> new ScanDetails(scan, jobsByScan.getOrDefault(scan.getId(), List.of())));
		});
	}

	private Optional<ScanRequestOutcome> findReplay(UUID projectId, String idempotencyKey, String fingerprint) {
		return this.readTransaction.execute((status) -> this.scans
			.findByProjectIdAndIdempotencyKey(projectId, idempotencyKey)
			.map((existing) -> {
				if (!existing.matchesFingerprint(fingerprint)) {
					throw new IdempotencyKeyReuseException();
				}
				return new ScanRequestOutcome(
						new ScanDetails(existing, this.scanJobs.findByScanIdOrderByScannerTypeAsc(existing.getId())),
						true);
			}));
	}

	private static void requireValidIdempotencyKey(String idempotencyKey) {
		if (!IDEMPOTENCY_KEY.matcher(idempotencyKey).matches()) {
			throw new DomainValidationException("Idempotency-Key",
					"must be 1-128 characters: letters, digits, '.', '_', ':' or '-'");
		}
	}

}
