package org.codehaus.groovy.grails.plugins.springsecurity

import org.grails.plugins.springsecurity.service.AuthenticateService

import org.springframework.context.ApplicationEvent
import org.springframework.context.ApplicationListener
import org.springframework.security.event.authentication.AbstractAuthenticationEvent
import org.springframework.security.event.authentication.AbstractAuthenticationFailureEvent
import org.springframework.security.event.authentication.AuthenticationSuccessEvent
import org.springframework.security.event.authentication.AuthenticationSwitchUserEvent
import org.springframework.security.event.authentication.InteractiveAuthenticationSuccessEvent
import org.springframework.security.event.authorization.AbstractAuthorizationEvent

/**
 * Registers as an event listener and delegates handling of security-related events
 * to optional closures defined in SecurityConfig.groovy.
 * <p/>
 * The following callbacks are supported:<br/>
 * <ul>
 * <li>onInteractiveAuthenticationSuccessEvent</li>
 * <li>onAbstractAuthenticationFailureEvent</li>
 * <li>onAuthenticationSuccessEvent</li>
 * <li>onAuthenticationSwitchUserEvent</li>
 * <li>onAuthorizationEvent</li>
 * </ul>
 * All callbacks are optional; you can implement just the ones you're interested in, e.g.
 * <pre>
 * security {
 *    active = true
 *
 *    onAuthenticationSuccessEvent = { e ->
 *       ...
 *    }
 * }
 * </pre>
 * @author <a href='mailto:beckwithb@studentsonly.com'>Burt Beckwith</a>
 */
class SecurityEventListener implements ApplicationListener {

	/**
	 * Dependency injection for AuthenticateService.
	 */
	AuthenticateService authenticateService

	/**
	 * {@inheritDoc}
	 * @see org.springframework.context.ApplicationListener#onApplicationEvent(
	 * 	org.springframework.context.ApplicationEvent)
	 */
	void onApplicationEvent(final ApplicationEvent e) {
		if (e instanceof AbstractAuthenticationEvent) {
			if (e instanceof InteractiveAuthenticationSuccessEvent) {
				if (config.onInteractiveAuthenticationSuccessEvent) {
					config.onInteractiveAuthenticationSuccessEvent.call((InteractiveAuthenticationSuccessEvent)e)
				}
			}
			else if (e instanceof AbstractAuthenticationFailureEvent) {
				if (config.onAbstractAuthenticationFailureEvent) {
					config.onAbstractAuthenticationFailureEvent.call((AbstractAuthenticationFailureEvent)e)
				}
			}
			else if (e instanceof AuthenticationSuccessEvent) {
				if (config.onAuthenticationSuccessEvent) {
					config.onAuthenticationSuccessEvent.call((AuthenticationSuccessEvent)e)
				}
			}
			else if (e instanceof AuthenticationSwitchUserEvent) {
				if (config.onAuthenticationSwitchUserEvent) {
//					GrailsUser userInfo = (GrailsUser)event.getAuthentication().getPrincipal()
//					UserDetails userDetails = event.getTargetUser()
					config.onAuthenticationSwitchUserEvent.call((AuthenticationSwitchUserEvent)e)
				}
			}
		}
		else if (e instanceof AbstractAuthorizationEvent) {
			if (config.onAuthorizationEvent) {
				config.onAuthorizationEvent.call((AbstractAuthorizationEvent)e)
			}
		}
	}

	private def getConfig() {
		return authenticateService.securityConfig.security
	}
}
