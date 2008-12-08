/*
 * Copyright 2007 the original author or authors.
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
import org.springframework.security.GrantedAuthority
import org.springframework.security.GrantedAuthorityImpl

/**
 * Unit tests for AuthorizeTools.
 *
 * @author <a href='mailto:beckwithb@studentsonly.com'>Burt Beckwith</a>
 */
class AuthorizeToolsTests extends AbstractSecurityTest {

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

	/**
	 * Test rolesToAuthorities().
	 */
	void testRolesToAuthorities() {
		def grantedRoles = ['role1', 'role2', 'role3']

		def granted = [new GrantedAuthorityImpl('role1'),
		               new GrantedAuthorityImpl('role2'),
		               new GrantedAuthorityImpl('role4')]

		def expected = ['role1', 'role2']
		assertSameContents expected, AuthorizeTools.rolesToAuthorities(grantedRoles, granted)
	}

	/**
	 * Check that two collections contain the same data, independent of collection class and order.
	 */
	private void assertSameContents(c1, c2) {
		assertEquals c1.size(), c2.size()
		assertTrue c1.containsAll(c2)
	}
}
