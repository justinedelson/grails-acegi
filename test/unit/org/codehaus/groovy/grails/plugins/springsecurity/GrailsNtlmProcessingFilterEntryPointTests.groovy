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
import org.springframework.mock.web.MockHttpServletResponse

/**
 * Unit tests for GrailsNtlmProcessingFilterEntryPoint.
 *
 * @author <a href='mailto:beckwithb@studentsonly.com'>Burt Beckwith</a>
 */
class GrailsNtlmProcessingFilterEntryPointTests extends AbstractSecurityTest {

	private final _entryPoint = new GrailsNtlmProcessingFilterEntryPoint()
	private final _request = new MockHttpServletRequest('GET', '/foo/bar')
	private final _response = new MockHttpServletResponse()

	void testCommence() {

		_entryPoint.commence _request, _response, null

		assertEquals 0, _request.session.getAttribute('SpringSecurityNtlm')
		assertEquals 'NTLM', _response.getHeader('WWW-Authenticate')
		assertEquals 'Keep-Alive', _response.getHeader('Connection')
		assertEquals 0, _response.contentLength
		assertEquals 401, _response.status
		assertTrue _response.committed
	}
}
