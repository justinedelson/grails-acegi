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
import org.springframework.security.GrantedAuthority
import org.springframework.security.GrantedAuthorityImpl
import org.springframework.security.ui.AbstractProcessingFilter as APF
import org.springframework.security.ui.savedrequest.SavedRequest
import org.springframework.security.util.PortResolverImpl

/**
 * Unit tests for AuthorizeTools.
 *
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
class AuthorizeToolsTests extends AbstractSecurityTest {

	/**
	 * {@inheritDoc}
	 * @see junit.framework.TestCase#setUp()
	 */
	@Override
	protected void setUp() {
		super.setUp()
		AuthorizeTools.ajaxHeaderName = 'ajaxHeader'
	}

	/**
	 * Test authoritiesToRoles().
	 */
	void testAuthoritiesToRoles() {

		def roleNames = []
		def authorities = []
		(1..10).each { i ->
			String name = "role${i}"
			roleNames << name
			authorities << new GrantedAuthorityImpl(name)
		}

		def roles = AuthorizeTools.authoritiesToRoles(authorities)
		assertSameContents roleNames, roles
	}

	/**
	 * Test authoritiesToRoles() when there is an authority with a null string.
	 */
	void testAuthoritiesToRolesNullAuthority() {

		def authority = EasyMock.createMock(GrantedAuthority)
		EasyMock.expect(authority.getAuthority()).andReturn(null)
		EasyMock.replay(authority)
		def authorities = [new GrantedAuthorityImpl('role1'), authority]

		shouldFail(IllegalArgumentException) {
			AuthorizeTools.authoritiesToRoles(authorities)
		}

		EasyMock.verify(authority)
	}

	/**
	 * Test getPrincipalAuthorities() when not authenticated.
	 */
	void testGetPrincipalAuthoritiesNoAuth() {
		assertTrue AuthorizeTools.getPrincipalAuthorities().empty
	}

	/**
	 * Test getPrincipalAuthorities() when not authenticated.
	 */
	void testGetPrincipalAuthoritiesNoRoles() {
		authenticate()
		assertTrue AuthorizeTools.getPrincipalAuthorities().empty
	}

	/**
	 * Test getPrincipalAuthorities().
	 */
	void testGetPrincipalAuthorities() {
		def authorities = []
		(1..10).each { i ->
			authorities << new GrantedAuthorityImpl("role${i}")
		}

		authenticate(null, null, authorities as GrantedAuthority[])

		assertEquals authorities, AuthorizeTools.getPrincipalAuthorities()
	}

	/**
	 * Test parseAuthoritiesString().
	 */
	void testParseAuthoritiesString() {
		String roleNames = 'role1,role2,role3'
		def roles = AuthorizeTools.parseAuthoritiesString(roleNames)

		assertEquals 3, roles.size()
		def expected = ['role1', 'role2', 'role3']
		def actual = roles.collect { authority -> authority.authority }
		assertSameContents expected, actual
	}

	/**
	 * Test retainAll().
	 */
	void testRetainAll() {
		def granted = [new GrantedAuthorityImpl('role1'),
		               new GrantedAuthorityImpl('role2'),
		               new GrantedAuthorityImpl('role3')]
		def required = [new GrantedAuthorityImpl('role1')]

		def expected = ['role1']
		assertSameContents expected, AuthorizeTools.retainAll(granted, required)
	}

	void testIsAjaxUsingParameterFalse() {
		assertFalse AuthorizeTools.isAjax(new MockHttpServletRequest())
	}

	void testIsAjaxUsingParameterTrue() {

		def request = new MockHttpServletRequest()
		request.setParameter('ajax', 'true')

		assertTrue AuthorizeTools.isAjax(request)
	}

	void testIsAjaxUsingHeaderFalse() {
		assertFalse AuthorizeTools.isAjax(new MockHttpServletRequest())
	}

	void testIsAjaxUsingHeaderTrue() {

		def request = new MockHttpServletRequest()
		request.addHeader('ajaxHeader', 'foo')

		assertTrue AuthorizeTools.isAjax(request)
	}

	void testIsAjaxUsingSavedRequestFalse() {

		def request = new MockHttpServletRequest()
		def savedRequest = new SavedRequest(request, new PortResolverImpl())
		request.session.setAttribute(APF.SPRING_SECURITY_SAVED_REQUEST_KEY, savedRequest)

		assertFalse AuthorizeTools.isAjax(request)
	}

	void testIsAjaxUsingSavedRequestTrue() {

		def request = new MockHttpServletRequest()
		request.addHeader 'ajaxHeader', 'true'
		def savedRequest = new SavedRequest(request, new PortResolverImpl())
		request.session.setAttribute(APF.SPRING_SECURITY_SAVED_REQUEST_KEY, savedRequest)

		assertTrue AuthorizeTools.isAjax(request)
	}

	void testIfAllGranted() {
		authenticate(['ROLE_1', 'ROLE_2'])
		assertTrue AuthorizeTools.ifAllGranted('ROLE_1')
		assertTrue AuthorizeTools.ifAllGranted('ROLE_2')
		assertTrue AuthorizeTools.ifAllGranted('ROLE_1,ROLE_2')
		assertFalse AuthorizeTools.ifAllGranted('ROLE_1,ROLE_2,ROLE_3')
		assertFalse AuthorizeTools.ifAllGranted('ROLE_3')
	}

	void testIfNotGranted() {
		authenticate(['ROLE_1', 'ROLE_2'])
		assertFalse AuthorizeTools.ifNotGranted('ROLE_1')
		assertFalse AuthorizeTools.ifNotGranted('ROLE_2')
		assertFalse AuthorizeTools.ifNotGranted('ROLE_1,ROLE_2')
		assertFalse AuthorizeTools.ifNotGranted('ROLE_1,ROLE_2,ROLE_3')
		assertTrue AuthorizeTools.ifNotGranted('ROLE_3')
	}

	void testIfAnyGranted() {
		authenticate(['ROLE_1', 'ROLE_2'])
		assertTrue AuthorizeTools.ifAnyGranted('ROLE_1')
		assertTrue AuthorizeTools.ifAnyGranted('ROLE_2')
		assertTrue AuthorizeTools.ifAnyGranted('ROLE_1,ROLE_2')
		assertTrue AuthorizeTools.ifAnyGranted('ROLE_1,ROLE_2,ROLE_3')
		assertFalse AuthorizeTools.ifAnyGranted('ROLE_3')
	}

	/**
	 * Check that two collections contain the same data, independent of collection class and order.
	 */
	private void assertSameContents(c1, c2) {
		assertEquals c1.size(), c2.size()
		assertTrue c1.containsAll(c2)
	}
}
