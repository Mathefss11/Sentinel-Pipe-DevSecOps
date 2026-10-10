package dev.sentinelpipe.api.common;

import java.net.URI;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.TypeMismatchException;
import org.springframework.core.MethodParameter;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.http.HttpHeaders;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.HttpMediaTypeNotSupportedException;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.validation.FieldError;
import org.springframework.validation.method.ParameterErrors;
import org.springframework.validation.method.ParameterValidationResult;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.method.annotation.HandlerMethodValidationException;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

/**
 * Translates exceptions into RFC 9457 Problem Details.
 *
 * <p>
 * Responses never include stack traces, exception class names, SQL, or rejected body,
 * parameter or header values. Validation problems carry an {@code errors} extension
 * listing the offending fields with fixed messages.
 *
 * <p>
 * The advice is global (not package-scoped) so that it also handles errors raised before
 * a handler is selected, such as 404, 405 and 415. Its presence replaces Spring Boot's
 * default Problem Details handler.
 */
@RestControllerAdvice
class ApiExceptionHandler extends ResponseEntityExceptionHandler {

	private static final Logger log = LoggerFactory.getLogger(ApiExceptionHandler.class);

	record FieldViolation(String field, String message) {
	}

	@ExceptionHandler(ResourceNotFoundException.class)
	ResponseEntity<ProblemDetail> handleNotFound(ResourceNotFoundException ex) {
		return problem(HttpStatus.NOT_FOUND, ProblemTypes.NOT_FOUND, "Resource not found",
				ex.getResourceType() + " was not found.");
	}

	@ExceptionHandler(ConflictException.class)
	ResponseEntity<ProblemDetail> handleConflict(ConflictException ex) {
		ResponseEntity<ProblemDetail> response = problem(HttpStatus.CONFLICT, ProblemTypes.CONFLICT, "Conflict",
				ex.getMessage());
		response.getBody().setProperty("code", ex.getCode());
		return response;
	}

	@ExceptionHandler(ForbiddenException.class)
	ResponseEntity<ProblemDetail> handleForbidden(ForbiddenException ex) {
		ResponseEntity<ProblemDetail> response = problem(HttpStatus.FORBIDDEN, ProblemTypes.FORBIDDEN, "Forbidden",
				ex.getMessage());
		response.getBody().setProperty("code", ex.getCode());
		return response;
	}

	/**
	 * Spring Security exceptions raised inside a handler must not fall through to the
	 * generic 500 handler. Authentication failures are 401; everything else is 403.
	 */
	@ExceptionHandler(AuthenticationException.class)
	ResponseEntity<ProblemDetail> handleAuthentication(AuthenticationException ex) {
		return problem(HttpStatus.UNAUTHORIZED, ProblemTypes.UNAUTHORIZED, "Unauthorized",
				"A valid bearer access token is required.");
	}

	@ExceptionHandler(AccessDeniedException.class)
	ResponseEntity<ProblemDetail> handleAccessDenied(AccessDeniedException ex) {
		return problem(HttpStatus.FORBIDDEN, ProblemTypes.FORBIDDEN, "Forbidden",
				"Access to this resource is not permitted.");
	}

	@ExceptionHandler(IdempotencyKeyReuseException.class)
	ResponseEntity<ProblemDetail> handleIdempotencyKeyReuse(IdempotencyKeyReuseException ex) {
		return problem(HttpStatus.UNPROCESSABLE_CONTENT, ProblemTypes.IDEMPOTENCY_KEY_REUSED,
				"Idempotency key reused", ex.getMessage() + ".");
	}

	@ExceptionHandler(DomainValidationException.class)
	ResponseEntity<ProblemDetail> handleDomainValidation(DomainValidationException ex) {
		return validationProblem(List.of(new FieldViolation(ex.getField(), ex.getMessage())));
	}

	@ExceptionHandler(DomainRuleViolationException.class)
	ResponseEntity<ProblemDetail> handleDomainRuleViolation(DomainRuleViolationException ex) {
		return problem(HttpStatus.CONFLICT, ProblemTypes.CONFLICT, "Conflict",
				"The operation is not permitted in the current state of the resource.");
	}

	@ExceptionHandler(OptimisticLockingFailureException.class)
	ResponseEntity<ProblemDetail> handleOptimisticLocking(OptimisticLockingFailureException ex) {
		return problem(HttpStatus.CONFLICT, ProblemTypes.CONFLICT, "Conflict",
				"The resource was modified concurrently. Retry the request.");
	}

	@ExceptionHandler(Exception.class)
	ResponseEntity<ProblemDetail> handleUnexpected(Exception ex) {
		log.error("Unhandled exception while processing an API request", ex);
		return problem(HttpStatus.INTERNAL_SERVER_ERROR, ProblemTypes.INTERNAL_ERROR, "Internal server error",
				"An unexpected error occurred.");
	}

	@Override
	protected ResponseEntity<Object> handleMethodArgumentNotValid(MethodArgumentNotValidException ex,
			HttpHeaders headers, HttpStatusCode status, WebRequest request) {
		List<FieldViolation> violations = new ArrayList<>();
		for (FieldError error : ex.getBindingResult().getFieldErrors()) {
			violations.add(new FieldViolation(error.getField(), error.getDefaultMessage()));
		}
		ex.getBindingResult()
			.getGlobalErrors()
			.forEach((error) -> violations.add(new FieldViolation(error.getObjectName(), error.getDefaultMessage())));
		return asObject(validationProblem(violations));
	}

	@Override
	protected ResponseEntity<Object> handleHandlerMethodValidationException(HandlerMethodValidationException ex,
			HttpHeaders headers, HttpStatusCode status, WebRequest request) {
		List<FieldViolation> violations = new ArrayList<>();
		for (ParameterValidationResult result : ex.getParameterValidationResults()) {
			if (result instanceof ParameterErrors errors) {
				// A validated request body: report its individual fields.
				errors.getFieldErrors()
					.forEach((error) -> violations.add(new FieldViolation(error.getField(), error.getDefaultMessage())));
				errors.getGlobalErrors()
					.forEach((error) -> violations
						.add(new FieldViolation(error.getObjectName(), error.getDefaultMessage())));
			}
			else {
				String name = parameterName(result.getMethodParameter());
				result.getResolvableErrors()
					.forEach((error) -> violations.add(new FieldViolation(name, error.getDefaultMessage())));
			}
		}
		return asObject(validationProblem(violations));
	}

	@Override
	protected ResponseEntity<Object> handleHttpMessageNotReadable(HttpMessageNotReadableException ex,
			HttpHeaders headers, HttpStatusCode status, WebRequest request) {
		return asObject(problem(HttpStatus.BAD_REQUEST, ProblemTypes.MALFORMED_REQUEST, "Malformed request",
				"The request body is missing, is not valid JSON, or contains unknown or invalid properties."));
	}

	@Override
	protected ResponseEntity<Object> handleHttpMediaTypeNotSupported(HttpMediaTypeNotSupportedException ex,
			HttpHeaders headers, HttpStatusCode status, WebRequest request) {
		ResponseEntity<ProblemDetail> response = problem(HttpStatus.UNSUPPORTED_MEDIA_TYPE, ProblemTypes.MALFORMED_REQUEST,
				"Unsupported media type", "The request Content-Type must be application/json.");
		return ResponseEntity.status(response.getStatusCode())
			.headers(headers)
			.body(response.getBody());
	}

	@Override
	protected ResponseEntity<Object> handleTypeMismatch(TypeMismatchException ex, HttpHeaders headers,
			HttpStatusCode status, WebRequest request) {
		String name = (ex instanceof MethodArgumentTypeMismatchException mismatch) ? mismatch.getName()
				: ex.getPropertyName();
		return asObject(validationProblem(List.of(new FieldViolation(name, "has an invalid format"))));
	}

	private static String parameterName(MethodParameter parameter) {
		PathVariable pathVariable = parameter.getParameterAnnotation(PathVariable.class);
		if (pathVariable != null && !pathVariable.name().isEmpty()) {
			return pathVariable.name();
		}
		RequestParam requestParam = parameter.getParameterAnnotation(RequestParam.class);
		if (requestParam != null && !requestParam.name().isEmpty()) {
			return requestParam.name();
		}
		RequestHeader requestHeader = parameter.getParameterAnnotation(RequestHeader.class);
		if (requestHeader != null && !requestHeader.name().isEmpty()) {
			return requestHeader.name();
		}
		return parameter.getParameterName();
	}

	private static ResponseEntity<ProblemDetail> validationProblem(List<FieldViolation> violations) {
		List<FieldViolation> sorted = violations.stream()
			.sorted(Comparator.comparing(FieldViolation::field).thenComparing(FieldViolation::message))
			.toList();
		ResponseEntity<ProblemDetail> response = problem(HttpStatus.BAD_REQUEST, ProblemTypes.VALIDATION_ERROR,
				"Validation failed", "The request contains invalid values.");
		response.getBody().setProperty("errors", sorted);
		return response;
	}

	private static ResponseEntity<ProblemDetail> problem(HttpStatus status, URI type, String title, String detail) {
		ProblemDetail problem = ProblemDetail.forStatusAndDetail(status, detail);
		problem.setType(type);
		problem.setTitle(title);
		return ResponseEntity.status(status).body(problem);
	}

	@SuppressWarnings({ "unchecked", "rawtypes" })
	private static ResponseEntity<Object> asObject(ResponseEntity<ProblemDetail> response) {
		return (ResponseEntity) response;
	}

}
