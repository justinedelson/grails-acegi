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
package org.codehaus.groovy.grails.plugins.springsecurity

import org.grails.plugins.springsecurity.test.TestingAuthenticationToken

import org.springframework.security.BadCredentialsException
import org.springframework.security.event.authentication.AuthenticationFailureBadCredentialsEvent
import org.springframework.security.event.authentication.AuthenticationSuccessEvent
import org.springframework.security.event.authentication.AuthenticationSwitchUserEvent
import org.springframework.security.event.authentication.InteractiveAuthenticationSuccessEvent
import org.springframework.security.event.authorization.AbstractAuthorizationEvent

/**
 * Unit tests for SecurityEventListener.
 *
 * @author <a href='mailto:beckwithb@studentsonly.com'>Burt Beckwith</a>
 */
class SecurityEventListenerTests extends AbstractSecurityTest {

	private _listener
	private _closures

	/**
	 * {@inheritDoc}
	 * @see junit.framework.TestCase#setUp()
	 */
	@Override
	protected void setUp() {
		super.setUp()
		_listener = new SecurityEventListener()
		_closures = new ConfigObject()
		_listener.securityConfig = _closures
	}

	/**
	 * Test handling <code>InteractiveAuthenticationSuccessEvent</code>.
	 */
	void testInteractiveAuthenticationSuccessEvent() {

		boolean called = false
		_closures.onInteractiveAuthenticationSuccessEvent = { e, appCtx -> called = true }

		_listener.onApplicationEvent(new InteractiveAuthenticationSuccessEvent(
				new TestingAuthenticationToken(), getClass()))

		assertTrue called
	}

	/**
	 * Test handling <code>AbstractAuthenticationFailureEvent</code>.
	 */
	void testAbstractAuthenticationFailureEvent() {

		boolean called = false
		_closures.onAbstractAuthenticationFailureEvent = { e, appCtx -> called = true }

		_listener.onApplicationEvent new AuthenticationFailureBadCredentialsEvent(
				new TestingAuthenticationToken(), new BadCredentialsException('bad credentials'))

		assertTrue called
	}

	/**
	 * Test handling <code>AuthenticationSuccessEvent</code>.
	 */
	void testAuthenticationSuccessEvent() {

		boolean called = false
		_closures.onAuthenticationSuccessEvent = { e, appCtx -> called = true }

		_listener.onApplicationEvent(new AuthenticationSuccessEvent(
				new TestingAuthenticationToken()))

		assertTrue called
	}

	/**
	 * Test handling <code>AbstractAuthorizationEvent</code>.
	 */
	void testAbstractAuthorizationEvent() {

		boolean called = false
		_closures.onAuthorizationEvent = { e, appCtx -> called = true }

		_listener.onApplicationEvent(new TestAuthorizationEvent())

		assertTrue called
	}
}

/**
 * Dummy event (should be an anonymous inner class, but not possible in Groovy).
 */
class TestAuthorizationEvent extends AbstractAuthorizationEvent {
	private static final long serialVersionUID = 7494437719452508589L

	TestAuthorizationEvent() {
		super(new Object())
	}
}
