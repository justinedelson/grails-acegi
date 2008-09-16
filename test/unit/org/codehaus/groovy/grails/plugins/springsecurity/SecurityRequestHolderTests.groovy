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
