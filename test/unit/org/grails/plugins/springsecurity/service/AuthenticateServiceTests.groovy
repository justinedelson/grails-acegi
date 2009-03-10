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
package org.grails.plugins.springsecurity.service

import groovy.util.Expando

import org.codehaus.groovy.grails.plugins.springsecurity.AbstractSecurityTest
import org.codehaus.groovy.grails.plugins.springsecurity.AuthorizeTools as AT
import org.codehaus.groovy.grails.plugins.springsecurity.GrailsUserImpl

import org.grails.plugins.springsecurity.test.TestingAuthenticationToken

import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.security.Authentication
import org.springframework.security.GrantedAuthority
import org.springframework.security.context.SecurityContextHolder as SCH
import org.springframework.security.ui.AbstractProcessingFilter as APF

/**
 * Unit tests for AuthenticateService.
 *
 * @author <a href='mailto:beckwithb@studentsonly.com'>Burt Beckwith</a>
 */
class AuthenticateServiceTests extends AbstractSecurityTest {

	private _service
	private final _user = new Object() // domain class instance

	private final MockHttpServletRequest _request = new MockHttpServletRequest()

	/**
	 * {@inheritDoc}
	 * @see junit.framework.TestCase#setUp()
	 */
	@Override
	protected void setUp() {
		super.setUp()
		_service = new AuthenticateService()
		_service.metaClass.getRequest = { -> _request }
	}

	/**
	 * Test transactional.
	 */
	void testTransactional() {
		assertFalse _service.transactional
	}

	/**
	 * Test principal() when authenticated.
	 */
	void testPrincipalAuthenticated() {
		authenticate('role1')
		assertNotNull _service.principal()
	}

	/**
	 * Test principal() when not authenticated.
	 */
	void testPrincipalNotAuthenticated() {
		assertNull _service.principal()
	}

	/**
	 * Test ifAllGranted().
	 */
	void testIfAllGranted() {
		authenticate('role1')
		assertFalse _service.ifAllGranted('role1,role2')

		authenticate('role2,role1')
		assertTrue _service.ifAllGranted('role1,role2')
	}

	/**
	 * Test ifNotGranted().
	 */
	void testIfNotGranted() {
		authenticate('role1')
		assertFalse _service.ifNotGranted('role1,role2')

		authenticate('role3')
		assertTrue _service.ifNotGranted('role1,role2')
	}

	/**
	 * Test ifAnyGranted().
	 */
	void testIfAnyGranted() {
		authenticate('role3')
		assertFalse _service.ifAnyGranted('role1,role2')

		authenticate('role1')
		assertTrue _service.ifAnyGranted('role1,role2')
	}

	/**
	 * Test userDomain() when not authenticated.
	 */
	void testUserDomainNotAuthenticated() {
		assertNull _service.userDomain()
	}

	/**
	 * Test userDomain() when authenticated.
	 */
	void testUserDomainAuthenticated() {
		authenticate('role1')
		_service.authenticationTrustResolver = [isAnonymous: { auth -> false }]
		assertEquals _user, _service.userDomain()
	}

	/**
	 * Test encodePassword().
	 */
	void testEncodePassword() {
		_service.passwordEncoder = [encodePassword: { String pwd, Object salt -> pwd + '_encoded' }]
		assertEquals 'passw0rd_encoded', _service.encodePassword('passw0rd')
	}

	/**
	 * Test passwordEncoder().
	 */
	void testPasswordEncoder() {
		_service.passwordEncoder = [encodePassword: { String pwd, Object salt -> pwd + '_encoded' }]
		assertEquals 'passw0rd_encoded', _service.passwordEncoder('passw0rd')
	}

	void testClearCachedRequestmaps() {
		boolean resetCalled = false
		_service.objectDefinitionSource = [reset: { -> resetCalled = true }]

		_service.clearCachedRequestmaps()

		assertTrue resetCalled
	}

	void testDeleteRole() {

		def requestmaps = [new TestRequestmap('ROLE_USER'),
		                   new TestRequestmap('ROLE_ADMIN'),
		                   new TestRequestmap('ROLE_ADMIN,ROLE_FOO'),
		                   new TestRequestmap('ROLE_USER,ROLE_ADMIN,ROLE_FOO'),
		                   new TestRequestmap('ROLE_USER,ROLE_ADMIN,ROLE_FOO'),
		                   new TestRequestmap('ROLE_ADMIN,ROLE_FOO')]
		_service.metaClass.findRequestmapsByRole = { String roleName, domainClass, conf -> requestmaps }

		def role = new TestRole()
		role.authority = 'ROLE_ADMIN'

		def conf = [security: [requestMapConfigAttributeField: 'configAttribute',
		                       useRequestMapDomainClass: true]]
		_service.metaClass.getSecurityConfig = { -> conf }

		boolean clearCachedRequestmapsCalled = false
		_service.metaClass.clearCachedRequestmaps = { -> clearCachedRequestmapsCalled = true }

		_service.deleteRole role

		assertEquals 'ROLE_USER', requestmaps[0].configAttribute
		assertTrue requestmaps[1].deleted
		assertEquals 'ROLE_FOO', requestmaps[2].configAttribute
		assertEquals 'ROLE_USER,ROLE_FOO', requestmaps[3].configAttribute
		assertEquals 'ROLE_USER,ROLE_FOO', requestmaps[4].configAttribute
		assertEquals 'ROLE_FOO', requestmaps[5].configAttribute

		assertTrue clearCachedRequestmapsCalled
		assertTrue role.deleted
	}

	void testUpdateRole() {

		def requestmaps = [new TestRequestmap('ROLE_USER'),
		                   new TestRequestmap('ROLE_ADMIN'),
		                   new TestRequestmap('ROLE_ADMIN,ROLE_FOO'),
		                   new TestRequestmap('ROLE_USER,ROLE_ADMIN,ROLE_FOO'),
		                   new TestRequestmap('ROLE_USER,ROLE_ADMIN,ROLE_FOO'),
		                   new TestRequestmap('ROLE_ADMIN,ROLE_FOO')]
		_service.metaClass.findRequestmapsByRole = { String roleName, domainClass, conf -> requestmaps }

		def role = new TestRole()
		role.authority = 'ROLE_ADMIN'

		def conf = [security: [requestMapConfigAttributeField: 'configAttribute',
		                       useRequestMapDomainClass: true]]
		_service.metaClass.getSecurityConfig = { -> conf }

		boolean clearCachedRequestmapsCalled = false
		_service.metaClass.clearCachedRequestmaps = { -> clearCachedRequestmapsCalled = true }

		assertTrue _service.updateRole(role, [authority: 'ROLE_SUPERADMIN'])

		assertEquals 'ROLE_USER', requestmaps[0].configAttribute
		assertEquals 'ROLE_SUPERADMIN', requestmaps[1].configAttribute
		assertEquals 'ROLE_SUPERADMIN,ROLE_FOO', requestmaps[2].configAttribute
		assertEquals 'ROLE_USER,ROLE_SUPERADMIN,ROLE_FOO', requestmaps[3].configAttribute
		assertEquals 'ROLE_USER,ROLE_SUPERADMIN,ROLE_FOO', requestmaps[4].configAttribute
		assertEquals 'ROLE_SUPERADMIN,ROLE_FOO', requestmaps[5].configAttribute

		assertTrue clearCachedRequestmapsCalled
		assertTrue role.saveCalled
	}

	void testIsAjax() {
		def request = new MockHttpServletRequest()

		assertFalse _service.isAjax(request)

		request.addHeader('ajaxHeader', 'foo')
		assertTrue _service.isAjax(request)
	}

	private void authenticate(roles) {
		GrantedAuthority[] authorities = AT.parseAuthoritiesString(roles) as GrantedAuthority[]
		def principal = new GrailsUserImpl(
				'username', 'password', true, true, true,
				true, authorities, _user)
		Authentication authentication = new TestingAuthenticationToken(
				principal, null, authorities)
		authentication.authenticated = true
		SCH.context.authentication = authentication
	}

	/**
	 * {@inheritDoc}
	 * @see junit.framework.TestCase#tearDown()
	 */
	@Override
	protected void tearDown() {
		super.tearDown()
		removeMetaClassMethods AuthenticateService
		fixMetaClass _service
	}
}

class TestRole {

	boolean saveCalled
	String authority
	boolean deleted

	void save() {
		saveCalled = true
	}

	boolean hasErrors() {
		return false
	}

	void setProperties(Map properties) {
		authority = properties.authority
	}

	void delete() {
		deleted = true
	}

	static void withTransaction(closure) {
		closure()
	}
}

class TestRequestmap {

	String configAttribute
	boolean deleted

	TestRequestmap(String configAttribute) {
		this.configAttribute = configAttribute
	}

	void delete() {
		deleted = true
	}
}
