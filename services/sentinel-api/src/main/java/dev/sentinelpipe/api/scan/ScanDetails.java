package dev.sentinelpipe.api.scan;

import dev.sentinelpipe.api.scanjob.ScanJob;
import java.util.List;

/** A scan together with its jobs, as read in one transaction. */
public record ScanDetails(Scan scan, List<ScanJob> jobs) {

	public ScanDetails {
		jobs = List.copyOf(jobs);
	}

}
