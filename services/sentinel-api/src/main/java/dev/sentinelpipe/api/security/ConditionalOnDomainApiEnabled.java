package dev.sentinelpipe.api.security;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBooleanProperty;

/**
 * Registers the annotated component only when {@code sentinel.domain-api.enabled=true}.
 *
 * <p>
 * The domain REST API is disabled by default: its controllers are not registered and the
 * security filter chain denies {@code /api/**}. When enabled, it requires valid JWT
 * configuration and a loopback binding. See {@link DomainApiExposureGuard}, ADR-0002 and
 * ADR-0003.
 */
@Documented
@Target({ ElementType.TYPE, ElementType.METHOD })
@Retention(RetentionPolicy.RUNTIME)
@ConditionalOnBooleanProperty(name = DomainApiExposureGuard.ENABLED_PROPERTY)
public @interface ConditionalOnDomainApiEnabled {

}
