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

import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse
import org.springframework.security.BadCredentialsException
import org.springframework.security.MockAuthenticationManager

import org.codehaus.groovy.grails.plugins.springsecurity.AbstractSecurityTest
import org.codehaus.groovy.grails.plugins.springsecurity.SecurityRequestHolder
/**
 * Unit tests for FacebookAuthenticationProcessingFilter.
 *
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
class FacebookAuthenticationProcessingFilterTests extends AbstractSecurityTest {

	private _filter = new TestFacebookAuthenticationProcessingFilter()

	void testSetLastUsername() {
		def request = new MockHttpServletRequest()
		request.getSession()
		long userId = 12345

		new FacebookAuthenticationProcessingFilter().setLastUsername userId, request

		assertEquals '12345', request.session.getAttribute('SPRING_SECURITY_LAST_USERNAME')
	}

	void testGetDefaultFilterProcessesUrl() {
		assertEquals '/j_spring_facebook_security_check', _filter.defaultFilterProcessesUrl
	}

	void testGetOrder() {
		assertEquals 801, _filter.order
	}

	void testAfterPropertiesSet() {

		String message = shouldFail(IllegalArgumentException) {
			_filter.afterPropertiesSet()
		}
		assertEquals 'defaultTargetUrl must be specified', message

		_filter.defaultTargetUrl = '/'

		message = shouldFail(IllegalArgumentException) {
			_filter.afterPropertiesSet()
		}
		assertEquals 'authenticationManager must be specified', message

		_filter.authenticationManager = new MockAuthenticationManager()

		message = shouldFail(IllegalArgumentException) {
			_filter.afterPropertiesSet()
		}
		assertEquals 'API key must be specified', message

		_filter.apiKey = 'apiKey'

		message = shouldFail(IllegalArgumentException) {
			_filter.afterPropertiesSet()
		}
		assertEquals 'Secret key must be specified', message

		_filter.secretKey = 'secretKey'
		_filter.afterPropertiesSet()
	}

	void testAttemptAuthentication() {

		def request = new MockHttpServletRequest()

		shouldFail(FacebookAuthenticationRequiredException) {
			_filter.attemptAuthentication request
		}

		request.setParameter 'auth_token', 'auth_token'

		_filter.apiKey = 'apiKey'
		_filter.secretKey = 'secretKey'
		_filter.authenticationManager = new MockAuthenticationManager()

		SecurityRequestHolder.set request, new MockHttpServletResponse()

		_filter.attemptAuthentication request

		assertEquals '123', request.session.getAttribute('SPRING_SECURITY_LAST_USERNAME')
	}

	void testDetermineFailureUrl() {
		_filter.authenticationUrlRoot = 'ROOT_'
		_filter.apiKey = 'KEY'

		def request = new MockHttpServletRequest()

		_filter.authenticationFailureUrl = 'FAIL_URL'

		assertEquals 'ROOT_KEY',
			_filter.determineFailureUrl(request, new FacebookAuthenticationRequiredException())

		assertEquals 'FAIL_URL',
			_filter.determineFailureUrl(request, new BadCredentialsException('bad credentials'))
	}

	/**
	 * {@inheritDoc}
	 * @see junit.framework.TestCase#tearDown()
	 */
	@Override
	protected void tearDown() {
		super.tearDown()
		SecurityRequestHolder.reset()
	}
}

class TestFacebookAuthenticationProcessingFilter extends FacebookAuthenticationProcessingFilter {

	protected FacebookAuthenticationToken createToken(
			String authToken, HttpServletRequest request, HttpServletResponse response,
			String apiKey, String secretKey) {

		def token = new FacebookAuthenticationToken(123L, 'sessionKey')
		token.authenticated = true
		return token
	}
}
