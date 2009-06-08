/* Copyright 2006-2009 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.codehaus.groovy.grails.plugins.springsecurity;

import groovy.lang.Closure;
import groovy.util.ConfigObject;

import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.security.event.authentication.AbstractAuthenticationEvent;
import org.springframework.security.event.authentication.AbstractAuthenticationFailureEvent;
import org.springframework.security.event.authentication.AuthenticationSuccessEvent;
import org.springframework.security.event.authentication.AuthenticationSwitchUserEvent;
import org.springframework.security.event.authentication.InteractiveAuthenticationSuccessEvent;
import org.springframework.security.event.authorization.AbstractAuthorizationEvent;

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
 *    onAuthenticationSuccessEvent = { e, appCtx ->
 *       ...
 *    }
 * }
 * </pre>
 * The event and the Spring context are provided in case you need to look up a Spring bean,
 * e.g. the Hibernate SessionFactory.
 *
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
public class SecurityEventListener implements ApplicationListener, ApplicationContextAware {

	private ApplicationContext _applicationContext;
	private ConfigObject _securityConfig;

	/**
	 * {@inheritDoc}
	 * @see org.springframework.context.ApplicationListener#onApplicationEvent(
	 * 	org.springframework.context.ApplicationEvent)
	 */
	public void onApplicationEvent(final ApplicationEvent e) {
		if (e instanceof AbstractAuthenticationEvent) {
			if (e instanceof InteractiveAuthenticationSuccessEvent) {
				call(e, "onInteractiveAuthenticationSuccessEvent");
			}
			else if (e instanceof AbstractAuthenticationFailureEvent) {
				call(e, "onAbstractAuthenticationFailureEvent");
			}
			else if (e instanceof AuthenticationSuccessEvent) {
				call(e, "onAuthenticationSuccessEvent");
			}
			else if (e instanceof AuthenticationSwitchUserEvent) {
//				GrailsUser userInfo = (GrailsUser)event.getAuthentication().getPrincipal()
//				UserDetails userDetails = event.getTargetUser()
				call(e, "onAuthenticationSwitchUserEvent");
			}
		}
		else if (e instanceof AbstractAuthorizationEvent) {
			call(e, "onAuthorizationEvent");
		}
	}

	private void call(final ApplicationEvent e, final String closureName) {
		Closure closure = (Closure)_securityConfig.get(closureName);
		if (closure != null) {
			closure.call(new Object[] { e, _applicationContext });
		}
	}

	/**
	 * Dependency injection for the security config.
	 * @param config  the config
	 */
	public void setSecurityConfig(final ConfigObject config) {
		_securityConfig = config;
	}

	/**
 	 * {@inheritDoc}
 	 * @see org.springframework.context.ApplicationContextAware#setApplicationContext(
 	 * 	org.springframework.context.ApplicationContext)
 	 */
 	public void setApplicationContext(final ApplicationContext applicationContext) {
 		_applicationContext = applicationContext;
 	}
}
