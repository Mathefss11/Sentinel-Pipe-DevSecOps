package dev.sentinelpipe.api.common;

/** Shared pagination bounds for collection endpoints. */
public final class Pagination {

	public static final String DEFAULT_PAGE = "0";

	public static final String DEFAULT_SIZE = "20";

	public static final int MAX_SIZE = 100;

	/** Bounds offset-based paging cost; deeper paging will move to keyset pagination. */
	public static final int MAX_PAGE = 10_000;

	private Pagination() {
	}

}
