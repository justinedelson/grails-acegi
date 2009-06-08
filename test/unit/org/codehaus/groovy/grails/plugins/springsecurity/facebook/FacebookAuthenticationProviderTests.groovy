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
package org.codehaus.groovy.grails.plugins.springsecurity.facebook

import org.springframework.security.AuthenticationServiceException
import org.springframework.security.BadCredentialsException
import org.springframework.security.GrantedAuthority
import org.springframework.security.GrantedAuthorityImpl
import org.springframework.security.providers.rememberme.RememberMeAuthenticationToken
import org.springframework.security.userdetails.UserDetails
import org.springframework.security.userdetails.UserDetailsService

import org.codehaus.groovy.grails.plugins.springsecurity.AbstractSecurityTest
import org.codehaus.groovy.grails.plugins.springsecurity.GrailsDaoImpl
import org.codehaus.groovy.grails.plugins.springsecurity.GrailsUserImpl

/**
 * Unit tests for FacebookAuthenticationProvider.
 *
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
class FacebookAuthenticationProviderTests extends AbstractSecurityTest {

	private _provider = new FacebookAuthenticationProvider()

	void testSupports() {
		assertTrue _provider.supports(FacebookAuthenticationToken)
		assertFalse _provider.supports(RememberMeAuthenticationToken)
	}

	void testAfterPropertiesSet() {
		String message = shouldFail(IllegalArgumentException) {
			_provider.afterPropertiesSet()
		}
		assertEquals 'The userDetailsService must be set', message

		_provider.userDetailsService = new GrailsDaoImpl()
		_provider.afterPropertiesSet()
	}

	void testAuthenticateFailure() {
		def authentication = new FacebookAuthenticationToken(
				FacebookAuthenticationToken.Status.failure, 'failed')

		shouldFail(BadCredentialsException) {
			_provider.authenticate authentication
		}
	}

	void testAuthenticateError() {
		def authentication = new FacebookAuthenticationToken(
				FacebookAuthenticationToken.Status.error, 'failed')

		shouldFail(AuthenticationServiceException) {
			_provider.authenticate authentication
		}
	}

	void testAuthenticateNotSupported() {
		assertNull _provider.authenticate(new RememberMeAuthenticationToken('key', 'username', null))
	}

	void testAuthenticateSuccess() {
		_provider.userDetailsService = new TestUserDetailsService()

		def authentication = _provider.authenticate(new FacebookAuthenticationToken(123L, 'sessionkey'))

		assertTrue authentication.authenticated
		assertEquals 123L, authentication.userId
		assertEquals 'sessionkey', authentication.sessionKey
		assertEquals 1, authentication.authorities.size()
	}
}

class TestUserDetailsService implements UserDetailsService {
	UserDetails loadUserByUsername(String username) {
		def authorities = [new GrantedAuthorityImpl('ROLE_USER')] as GrantedAuthority[]
		return new GrailsUserImpl(username, 'password', true, true, true, true, authorities, null)
	}
}
