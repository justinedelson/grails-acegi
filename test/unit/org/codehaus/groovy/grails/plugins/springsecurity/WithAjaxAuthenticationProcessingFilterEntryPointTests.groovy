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
import org.springframework.security.AuthenticationException

/**
 * Unit tests for WithAjaxAuthenticationProcessingFilterEntryPoint.
 *
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
class WithAjaxAuthenticationProcessingFilterEntryPointTests extends GroovyTestCase {

	private final _entryPoint = new WithAjaxAuthenticationProcessingFilterEntryPoint()

	private String _loginFormUrl = '/loginFormUrl'
	private String _ajaxLoginFormUrl = '/ajaxLoginFormUrl'

	/**
	 * Test commence() with Ajax false.
	 */
	void testCommenceNotAjax() {

		MockHttpServletRequest request = new MockHttpServletRequest()
		MockHttpServletResponse response = new MockHttpServletResponse()

		_entryPoint.commence(request, response, null)

		assertEquals _loginFormUrl, response.forwardedUrl
	}

	/**
	 * Test commence() with Ajax true.
	 */
	void testCommenceAjax() {

		MockHttpServletRequest request = new MockHttpServletRequest()
		MockHttpServletResponse response = new MockHttpServletResponse()

		_entryPoint.ajaxHeader = 'ajax_header'
		request.addHeader('ajax_header', 'XHR')

		_entryPoint.commence(request, response, null)

		assertEquals _ajaxLoginFormUrl, response.forwardedUrl
	}

	/**
	 * Test setAjaxLoginFormUrl().
	 */
	void testSetAjaxLoginFormUrl() {
		shouldFail(IllegalArgumentException) {
			_entryPoint.ajaxLoginFormUrl = 'foo'
		}

		_entryPoint.ajaxLoginFormUrl = '/foo'
	}

	/**
	 * {@inheritDoc}
	 * @see junit.framework.TestCase#setUp()
	 */
	@Override
	protected void setUp() {
		super.setUp()
		_entryPoint.serverSideRedirect = true
		_entryPoint.loginFormUrl = _loginFormUrl
		_entryPoint.ajaxLoginFormUrl = _ajaxLoginFormUrl
	}
}
