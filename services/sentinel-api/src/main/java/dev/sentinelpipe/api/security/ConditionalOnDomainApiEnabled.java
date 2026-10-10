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
 * The domain REST API has no authentication or tenant authorization yet, so its
 * controllers are not registered by default and their routes do not exist. See
 * {@link DomainApiExposureGuard} and ADR-0002.
 */
@Documented
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@ConditionalOnBooleanProperty(name = DomainApiExposureGuard.ENABLED_PROPERTY)
public @interface ConditionalOnDomainApiEnabled {

}
