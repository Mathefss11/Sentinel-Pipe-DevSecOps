package dev.sentinelpipe.api.common;

import java.util.List;
import java.util.function.Function;
import org.springframework.data.domain.Page;

/**
 * Stable pagination envelope for collection endpoints. Spring Data's {@link Page} is not
 * serialized directly, so the public contract does not depend on framework internals.
 */
public record PageResponse<T>(List<T> items, PageMetadata page) {

	public record PageMetadata(int number, int size, long totalElements, int totalPages) {
	}

	public static <E, T> PageResponse<T> of(Page<E> page, Function<E, T> mapper) {
		return of(page, page.getContent().stream().map(mapper).toList());
	}

	public static <T> PageResponse<T> of(Page<?> page, List<T> items) {
		return new PageResponse<>(items,
				new PageMetadata(page.getNumber(), page.getSize(), page.getTotalElements(), page.getTotalPages()));
	}

}
