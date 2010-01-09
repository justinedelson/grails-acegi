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

import javax.servlet.http.Cookie

import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse

/**
 * Unit tests for FacebookAuthenticationProvider.
 *
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
class FacebookLogoutHandlerTests extends GroovyTestCase {

	private _handler = new FacebookLogoutHandler()

	void testafterPropertiesSet() {
		String message = shouldFail(IllegalArgumentException) {
			_handler.afterPropertiesSet()
		}
		assertEquals 'API key must be specified', message

		_handler.apiKey = 'apiKey'
		_handler.afterPropertiesSet()
	}

	void testCancelCookie() {

		String name = 'cookie'
		String path = '/'
		def response = new MockHttpServletResponse()
		_handler.cancelCookie name, path, response

		assertEquals 1, response.cookies.length
		def cookie = response.cookies[0]
		assertEquals 0, cookie.maxAge
		assertEquals path, cookie.path
		assertEquals name, cookie.name
	}

	void testLogout() {
		def request = new MockHttpServletRequest()
		def response = new MockHttpServletResponse()

		_handler.apiKey = 'apiKey'

		String name = 'apiKey_foo'
		String path = '/'
		Cookie cookie = new Cookie(name, null)
		cookie.maxAge = 12345
		cookie.path = path
		request.cookies = cookie as Cookie[]

		_handler.logout request, response, null

		assertEquals 1, response.cookies.length
		cookie = response.cookies[0]
		assertEquals 0, cookie.maxAge
		assertEquals path, cookie.path
		assertEquals name, cookie.name
	}
}
