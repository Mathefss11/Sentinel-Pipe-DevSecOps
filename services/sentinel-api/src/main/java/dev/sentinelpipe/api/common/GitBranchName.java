package dev.sentinelpipe.api.common;

import jakarta.validation.Constraint;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import jakarta.validation.Payload;
import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Bean Validation constraint for {@link GitBranchNames}. {@code null} is considered valid;
 * combine with {@code @NotNull} where the value is required.
 */
@Documented
@Constraint(validatedBy = GitBranchName.Validator.class)
@Target({ ElementType.FIELD, ElementType.PARAMETER, ElementType.RECORD_COMPONENT })
@Retention(RetentionPolicy.RUNTIME)
public @interface GitBranchName {

	String message() default "must be a valid Git branch name";

	Class<?>[] groups() default {};

	Class<? extends Payload>[] payload() default {};

	class Validator implements ConstraintValidator<GitBranchName, String> {

		@Override
		public boolean isValid(String value, ConstraintValidatorContext context) {
			return value == null || GitBranchNames.isValid(value);
		}

	}

}
