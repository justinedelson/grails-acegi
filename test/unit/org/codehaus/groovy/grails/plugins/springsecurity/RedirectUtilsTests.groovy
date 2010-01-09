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

import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.security.GrantedAuthority
import org.springframework.security.GrantedAuthorityImpl

/**
* Unit tests for <code>RedirectUtils</code>.
*
* @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
*/
class RedirectUtilsTests extends GroovyTestCase {

	void testBuildRedirectUrlAbsolute() {
		String url = 'http://www.foo.com'
		assertEquals url, RedirectUtils.buildRedirectUrl(null, null, url)

		url = 'https://www.foo.com'
		assertEquals url, RedirectUtils.buildRedirectUrl(null, null, url)
	}

	void testBuildRedirectUrlNonstandardPort() {
		String url = '/wahoo'
		MockHttpServletRequest request = new MockHttpServletRequest()
		request.setContextPath('')
		request.setServerName('www.theserver.com')
		request.setServerPort(8080)
		request.setRequestURI('/bar')

		assertEquals 'http://www.theserver.com:8080/wahoo',
				RedirectUtils.buildRedirectUrl(request, null, url)
	}

	void testPrivateConstructor() {
		SecurityTestUtils.testPrivateConstructor RedirectUtils
	}
}
