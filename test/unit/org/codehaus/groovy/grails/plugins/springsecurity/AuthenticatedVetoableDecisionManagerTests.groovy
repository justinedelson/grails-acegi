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

import org.springframework.security.AccessDeniedException
import org.springframework.security.Authentication
import org.springframework.security.ConfigAttributeDefinition
import org.springframework.security.GrantedAuthority
import org.springframework.security.GrantedAuthorityImpl
import org.springframework.security.providers.anonymous.AnonymousAuthenticationToken
import org.springframework.security.providers.rememberme.RememberMeAuthenticationToken
import org.springframework.security.vote.AuthenticatedVoter
import org.springframework.security.vote.RoleVoter
import org.grails.plugins.springsecurity.test.TestingAuthenticationToken
/**
 * Unit tests for AuthenticatedVetoableDecisionManager.
 *
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
class AuthenticatedVetoableDecisionManagerTests extends AbstractSecurityTest {

	private _manager

	/**
	 * {@inheritDoc}
	 * @see junit.framework.TestCase#setUp()
	 */
	@Override
	protected void setUp() {
		super.setUp()
		_manager = new AuthenticatedVetoableDecisionManager()
		_manager.decisionVoters = [new AuthenticatedVoter(), new RoleVoter()]
	}

	void testDecideHasOneRole() {
		_manager.decide createAuthentication(['ROLE_USER']), null, createDefinition(['ROLE_USER', 'ROLE_ADMIN'])
	}

	void testDecideHasMoreThanRequiredRoles() {
		_manager.decide createAuthentication(['ROLE_USER', 'ROLE_ADMIN']), null, createDefinition(['ROLE_USER'])
	}

	void testDecideInsufficientRoles() {
		shouldFail(AccessDeniedException) {
			_manager.decide createAuthentication(['ROLE_USER']), null, createDefinition(['ROLE_ADMIN'])
		}
	}

	void testDecideAuthenticatedFully() {
		_manager.decide createAuthentication(['ROLE_USER']), null, createDefinition(['ROLE_USER', 'IS_AUTHENTICATED_FULLY'])
	}

	void testDecideAuthenticatedFullyRemembered() {
		def auth = new RememberMeAuthenticationToken('key', 'principal', namesToAuthorities(['ROLE_USER']))
		shouldFail(AccessDeniedException) {
			_manager.decide auth, null, createDefinition(['ROLE_USER', 'IS_AUTHENTICATED_FULLY'])
		}
	}

	void testDecideAuthenticatedFullyAnonymous() {
		def auth = new AnonymousAuthenticationToken('key', 'principal', namesToAuthorities(['ROLE_USER']))
		shouldFail(AccessDeniedException) {
			_manager.decide auth, null, createDefinition(['ROLE_USER', 'IS_AUTHENTICATED_FULLY'])
		}
	}

	private Authentication createAuthentication(roleNames) {
		return new TestingAuthenticationToken(null, null, namesToAuthorities(roleNames))
	}

	private GrantedAuthority[] namesToAuthorities(roleNames) {
		return roleNames.collect { new GrantedAuthorityImpl(it) } as GrantedAuthority[]
	}

	private ConfigAttributeDefinition createDefinition(roleNames) {
		return new ConfigAttributeDefinition(roleNames as String[])
	}
}
