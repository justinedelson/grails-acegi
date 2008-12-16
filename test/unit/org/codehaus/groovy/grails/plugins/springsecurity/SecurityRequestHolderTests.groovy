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
/**
 * Unit tests for <code>SecurityRequestHolder</code>.
 *
 * @author <a href='mailto:beckwithb@studentsonly.com'>Burt Beckwith</a>
 */
class SecurityRequestHolderTests extends AbstractSecurityTest {

	void testSetAndGet() {
		def request = new MockHttpServletRequest()
		assertNull SecurityRequestHolder.getRequest()
		SecurityRequestHolder.setRequest(request)
		assertSame request, SecurityRequestHolder.getRequest()
	}

	void testReset() {
		def request = new MockHttpServletRequest()
		assertNull SecurityRequestHolder.getRequest()
		SecurityRequestHolder.setRequest(request)
		assertSame request, SecurityRequestHolder.getRequest()

		SecurityRequestHolder.reset()
		assertNull SecurityRequestHolder.getRequest()
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
