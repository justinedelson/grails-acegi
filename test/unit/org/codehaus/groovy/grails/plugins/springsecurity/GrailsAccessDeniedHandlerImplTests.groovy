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

import org.easymock.EasyMock
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse
import org.springframework.security.AccessDeniedException
import org.springframework.security.AuthenticationTrustResolverImpl
import org.springframework.security.util.PortResolverImpl

/**
 * Unit tests for GrailsAccessDeniedHandlerImpl.
 *
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
class GrailsAccessDeniedHandlerImplTests extends AbstractSecurityTest {

	private _handler = new GrailsAccessDeniedHandlerImpl()
	private _request = new MockHttpServletRequest('GET', '/foo/bar')
	private _response = new MockHttpServletResponse()
	private String _message = 'denied'
	private _e = new AccessDeniedException(_message)

	/**
	 * {@inheritDoc}
	 * @see junit.framework.TestCase#setUp()
	 */
	@Override
	protected void setUp() {
		super.setUp()
		_handler.portResolver = new PortResolverImpl()
	}

	/**
	 * Test handle() when there's no error page set.
	 */
	void testHandleNoErrorPage() {

		_handler.handle(_request, _response, _e)

		assertEquals 403, _response.status
		assertEquals _message, _response.errorMessage
	}

	/**
	 * Test handle() when there's an error page set.
	 */
	void testHandleErrorPage() {

		_handler.errorPage = '/error'

		_handler.handle(_request, _response, _e)

		assertEquals 'http://localhost/error', _response.redirectedUrl
	}

	/**
	 * Test handle() when there's an error page set and the server port isn't 80.
	 */
	void testHandleErrorPageNonstandardPort() {

		_handler.errorPage = '/error'
		_request.serverPort = 90

		_handler.handle(_request, _response, _e)

		assertEquals 'http://localhost:90/error', _response.redirectedUrl
	}

	/**
	 * Test handle() when there's an error page set and the request is secure.
	 */
	void testHandleErrorPageSecure() {

		_handler.errorPage = '/error'
		_request.scheme = 'https'

		_handler.handle(_request, _response, _e)

		assertEquals 'https://localhost/error', _response.redirectedUrl
	}

	/**
	 * Test handle() when there's an error page set, the request is secure, and the port isn't 443.
	 */
	void testHandleErrorPageSecureNonstandardPort() {

		_handler.errorPage = '/error'
		_request.scheme = 'https'
		_request.serverPort = 9443

		_handler.handle(_request, _response, _e)

		assertEquals 'https://localhost:9443/error', _response.redirectedUrl
	}

	/**
	 * Test handle() when there's an Ajax error page set.
	 */
	void testHandleAjaxErrorPage() {

		_handler.ajaxErrorPage = '/errorAjax'
		_request.addHeader(WithAjaxAuthenticationProcessingFilterEntryPoint.AJAX_HEADER, 'XHR')

		_handler.handle(_request, _response, _e)

		assertEquals 'http://localhost/errorAjax', _response.redirectedUrl
	}

	/**
	 * Test handle() for Ajax request when there's no Ajax error page set.
	 */
	void testHandleAjaxNoErrorPage() {

		_request.addHeader(WithAjaxAuthenticationProcessingFilterEntryPoint.AJAX_HEADER, 'XHR')

		_handler.handle(_request, _response, _e)

		assertEquals 403, _response.status
		assertEquals _message, _response.errorMessage
	}

	/**
	 * Test setErrorPage().
	 */
	void testSetErrorPage() {
		shouldFail(IllegalArgumentException) {
			_handler.errorPage = 'foo'
		}

		_handler.errorPage = '/foo'
	}

	/**
	 * Test setAjaxErrorPage().
	 */
	void testSetAjaxErrorPage() {
		shouldFail(IllegalArgumentException) {
			_handler.ajaxErrorPage = 'foo'
		}

		_handler.ajaxErrorPage = '/foo'
	}

	void testAfterPropertiesSet() {

		String message = shouldFail(IllegalArgumentException) {
			_handler.afterPropertiesSet()
		}
		assertEquals 'authenticationTrustResolver is required', message

		_handler.authenticationTrustResolver = new AuthenticationTrustResolverImpl()
		_handler.ajaxHeader = 'AjaxHeader'
		_handler.afterPropertiesSet()
	}

	void testIsLoggedIn() {
		assertFalse _handler.isLoggedIn()

		authenticate()

		_handler.authenticationTrustResolver = new AuthenticationTrustResolverImpl()
		assertTrue _handler.isLoggedIn()
	}
}
