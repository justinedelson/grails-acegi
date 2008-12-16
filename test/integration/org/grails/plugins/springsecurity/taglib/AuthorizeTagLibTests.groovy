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
package org.grails.plugins.springsecurity.taglib

import grails.test.GroovyPagesTestCase

import org.codehaus.groovy.grails.plugins.springsecurity.AuthorizeTools
import org.codehaus.groovy.grails.plugins.springsecurity.GrailsUserImpl

import org.grails.plugins.springsecurity.test.TestingAuthenticationToken

import org.springframework.security.Authentication
import org.springframework.security.GrantedAuthority
import org.springframework.security.context.SecurityContextHolder as SCH
import org.springframework.security.userdetails.User

/**
 * Integration tests for <code>AuthorizeTagLib</code>.
 *
 * @author <a href='mailto:beckwithb@studentsonly.com'>Burt Beckwith</a>
 */
class AuthorizeTagLibTests extends GroovyPagesTestCase {

	private final Expando _user = new Expando()

	def transactional = false

	/**
	 * Test ifAllGranted().
	 */
	void testIfAllGranted() {
		String body = 'the_content'

		authenticate 'role1'
		assertOutputEquals '', "<g:ifAllGranted role='role1,role2'>${body}</g:ifAllGranted>"

		authenticate 'role2,role1'
		assertOutputEquals body, "<g:ifAllGranted role='role1,role2'>${body}</g:ifAllGranted>"
	}

	/**
	 * Test ifNotGranted().
	 */
	void testIfNotGrantedMissingRole() {
		String body = 'the_content'

		authenticate 'role1'
		assertOutputEquals '', "<g:ifNotGranted role='role1,role2'>${body}</g:ifNotGranted>"

		authenticate 'role3'
		assertOutputEquals body, "<g:ifNotGranted role='role1,role2'>${body}</g:ifNotGranted>"
	}

	/**
	 * Test ifAnyGranted().
	 */
	void testIfAnyGranted() {
		String body = 'the_content'

		authenticate 'role3'
		assertOutputEquals '', "<g:ifAnyGranted role='role1,role2'>${body}</g:ifAnyGranted>"

		authenticate 'role2'
		assertOutputEquals body, "<g:ifAnyGranted role='role1,role2'>${body}</g:ifAnyGranted>"
	}

	/**
	 * Test isLoggedIn().
	 */
	void testIsLoggedInTrue() {
		String body = 'the_content'

		assertOutputEquals '', "<g:isLoggedIn role='role1,role2'>${body}</g:isLoggedIn>"

		authenticate 'role1'
		assertOutputEquals body, "<g:isLoggedIn role='role1,role2'>${body}</g:isLoggedIn>"
	}

	/**
	 * Test isNotLoggedIn().
	 */
	void testIsNotLoggedIn() {
		String body = 'the_content'

		assertOutputEquals body, "<g:isNotLoggedIn role='role1,role2'>${body}</g:isNotLoggedIn>"

		authenticate 'role1'
		assertOutputEquals '', "<g:isNotLoggedIn role='role1,role2'>${body}</g:isNotLoggedIn>"
	}

	/**
	 * Test loggedInUserInfo() for a principal that has a 'domainClass' property.
	 */
	void testLoggedInUserInfoWithDomainClass() {
		String fullName = 'First Last'
		_user.fullName = fullName

		assertOutputEquals '', "<g:loggedInUserInfo field='fullName'/>"

		def principal = new HasDomainClass('username', fullName, 'role1', _user)
		authenticate principal, 'role1'

		assertOutputEquals fullName, "<g:loggedInUserInfo field='fullName'/>"
	}

	/**
	 * Test loggedInUserInfo() for a principal that doesn't have a 'domainClass' property.
	 */
	void testLoggedInUserInfoWithoutDomainClass() {
		String fullName = 'First Last'
		_user.fullName = fullName

		assertOutputEquals '', "<g:loggedInUserInfo field='fullName'/>"

		def principal = new NoDomainClass('username', fullName, 'role1')
		authenticate principal, 'role1'

		assertOutputEquals fullName, "<g:loggedInUserInfo field='fullName'/>"
	}

	void testLoggedInUsername() {
		assertOutputEquals '', "<g:loggedInUsername/>"

		authenticate 'role1'
		assertOutputEquals 'username1', "<g:loggedInUsername/>"
	}

	private void authenticate(String roles) {

		def principal = new Expando(username: 'username1')
		principal.domainClass = _user

		authenticate principal, roles
	}

	private void authenticate(principal, String roles) {
		Authentication authentication = new TestingAuthenticationToken(
				principal, null, parseRoles(roles))
		authentication.authenticated = true
		SCH.context.authentication = authentication
	}

	private GrantedAuthority[] parseRoles(String roles) {
		return AuthorizeTools.parseAuthoritiesString(roles)
	}

	/**
	 * {@inheritDoc}
	 * @see junit.framework.TestCase#tearDown()
	 */
	@Override
	protected void tearDown() {
		super.tearDown()
		SCH.context.authentication = null
	}
}

class NoDomainClass extends User {

	private final String _fullName

	NoDomainClass(String username, String fullName, String roles) {
		super(username, 'password', true, true, true, true,
				AuthorizeTools.parseAuthoritiesString(roles) as GrantedAuthority[])
		_fullName = fullName
	}

	String getFullName() {
		return _fullName
	}
}

class HasDomainClass extends GrailsUserImpl {

	private final String _fullName

	HasDomainClass(String username, String fullName, String roles, domainClass) {
		super(username, 'password', true, true, true, true,
				AuthorizeTools.parseAuthoritiesString(roles) as GrantedAuthority[],
				domainClass)
				_fullName = fullName
	}

	String getFullName() {
		return _fullName
	}
}
