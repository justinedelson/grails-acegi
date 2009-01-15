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
package org.codehaus.groovy.grails.plugins.springsecurity.openid

import org.codehaus.groovy.grails.plugins.springsecurity.AbstractSecurityTest
import org.codehaus.groovy.grails.plugins.springsecurity.GrailsUserImpl
import org.grails.plugins.springsecurity.test.TestingAuthenticationToken

import org.springframework.security.AuthenticationServiceException
import org.springframework.security.BadCredentialsException
import org.springframework.security.GrantedAuthority
import org.springframework.security.GrantedAuthorityImpl
import org.springframework.security.providers.openid.AuthenticationCancelledException
import org.springframework.security.providers.openid.OpenIDAuthenticationStatus
import org.springframework.security.providers.openid.OpenIDAuthenticationToken
import org.springframework.security.userdetails.UserDetailsService
/**
 * Unit tests for <code>GrailsOpenIdAuthenticationProvider</code>.
 *
 * @author <a href='mailto:beckwithb@studentsonly.com'>Burt Beckwith</a>
 */
class GrailsOpenIdAuthenticationProviderTests extends AbstractSecurityTest {

	private _provider = new GrailsOpenIdAuthenticationProvider()

	void testAuthenticateNotSupported() {

		def authentication = new TestingAuthenticationToken()
		assertNull _provider.authenticate(authentication)
	}

	void testAuthenticateStatusCancelled() {
		def authentication = new OpenIDAuthenticationToken(OpenIDAuthenticationStatus.CANCELLED, null, null)
		shouldFail(AuthenticationCancelledException) {
			_provider.authenticate(authentication)
		}
	}

	void testAuthenticateStatusError() {
		def authentication = new OpenIDAuthenticationToken(OpenIDAuthenticationStatus.ERROR, null, null)
		shouldFail(AuthenticationServiceException) {
			_provider.authenticate(authentication)
		}
	}

	void testAuthenticateStatusFailure() {
		def authentication = new OpenIDAuthenticationToken(OpenIDAuthenticationStatus.FAILURE, null, null)
		shouldFail(BadCredentialsException) {
			_provider.authenticate(authentication)
		}
	}

	void testAuthenticateStatusSetupNeeded() {
		def authentication = new OpenIDAuthenticationToken(OpenIDAuthenticationStatus.SETUP_NEEDED, null, null)
		shouldFail(AuthenticationServiceException) {
			_provider.authenticate(authentication)
		}
	}

	void testAuthenticateUnexpectedStatus() {
		def authentication = new OpenIDAuthenticationToken(new OpenIDAuthenticationStatus('foo'), null, null)
		try {
			_provider.authenticate(authentication)
			fail 'should have failed with AuthenticationServiceException'
		}
		catch (AuthenticationServiceException e) {
			assertEquals "Unrecognized return value foo", e.message
		}
	}

	void testAuthenticateSuccess() {
		String url = 'the_url'
		def authentication = new OpenIDAuthenticationToken(OpenIDAuthenticationStatus.SUCCESS, url, null)
		def roles = [new GrantedAuthorityImpl('role1')] as GrantedAuthority[]
		def details = new GrailsUserImpl('username', 'password', true, true, true, true, roles, null)
		_provider.@_userDetailsService = [loadUserByUsername: { identityUrl -> details }] as UserDetailsService

		def token = _provider.authenticate(authentication)
		assertNotNull token

		assertSame details, token.principal
		assertEquals url, token.identityUrl
		assertEquals OpenIDAuthenticationStatus.SUCCESS, token.getStatus()
	}
}
