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
import org.hibernate.Query
import org.hibernate.Session
import org.springframework.security.GrantedAuthorityImpl
import org.springframework.security.userdetails.UserDetails
import org.springframework.security.userdetails.UsernameNotFoundException

/**
 * Integration tests for <code>GrailsDaoImpl</code>.
 *
 * @author <a href='mailto:beckwithb@studentsonly.com'>Burt Beckwith</a>
 */
class GrailsDaoImplTests extends AbstractSecurityTest {

	private _dao

	/**
	 * {@inheritDoc}
	 * @see junit.framework.TestCase#setUp()
	 */
	@Override
	protected void setUp() {
		super.setUp()
		_dao = new GrailsDaoImpl()
		_dao.loginUserDomainClass = 'User'
		_dao.usernameFieldName = 'username'
	}

	/**
	 * Test loadUserByUsername() when user not found.
	 */
	void testLoadUserByUsernameNotFound() {

		String username = 'not_a_user'

		Session session = EasyMock.createMock(Session)
		Query query = EasyMock.createMock(Query)
		EasyMock.expect(session.createQuery('from User where username=:username')).andReturn(query)
		EasyMock.expect(query.list()).andReturn([])
		EasyMock.expect(query.setString('username', username)).andReturn(query)
		EasyMock.expect(query.setCacheable(true)).andReturn(query)

		EasyMock.replay session, query

		def container = new GrailsWebApplicationObjectSupport.SessionContainer(session, true)

		// replace definition to avoid going to the database
		_dao.metaClass.setUpSession = { -> container }

		_dao.authenticateService = [securityConfig: [security: [useNtlm: false]]]

		shouldFail(UsernameNotFoundException) {
			_dao.loadUserByUsername(username)
		}

		EasyMock.verify session, query
	}

	/**
	 * Test loadUserByUsername() when user has no roles.
	 */
	void testLoadUserByUsernameNoRoles() {

		String username = 'a_user'
		def user = new Expando()

		Session session = EasyMock.createMock(Session)
		Query query = EasyMock.createMock(Query)
		EasyMock.expect(session.createQuery('from User where username=:username')).andReturn(query)
		EasyMock.expect(query.setString('username', username)).andReturn(query)
		EasyMock.expect(query.setCacheable(true)).andReturn(query)
		EasyMock.expect(query.list()).andReturn([user])

		EasyMock.replay session, query

		def container = new GrailsWebApplicationObjectSupport.SessionContainer(session, true)

		// replace definition to avoid going to the database
		_dao.metaClass.setUpSession = { -> container }

		_dao.authoritiesMethodName = 'getRoles'
		user.getRoles = { -> [] }

		_dao.authenticateService = [securityConfig: [security: [useNtlm: false]]]

		def message = shouldFail(UsernameNotFoundException) {
			_dao.loadUserByUsername(username)
		}
		assertEquals 'User has no GrantedAuthority', message

		EasyMock.verify session, query
	}

	/**
	 * Test loadUserByUsername().
	 */
	void testLoadUserByUsername() {

		String username = 'a_user'
		def user = new Expando()

		Session session = EasyMock.createMock(Session)
		Query query = EasyMock.createMock(Query)
		EasyMock.expect(session.createQuery('from User where username=:username')).andReturn(query)
		EasyMock.expect(query.setString('username', username)).andReturn(query)
		EasyMock.expect(query.setCacheable(true)).andReturn(query)
		EasyMock.expect(query.list()).andReturn([user])

		EasyMock.replay session, query

		def container = new GrailsWebApplicationObjectSupport.SessionContainer(session, true)

		// replace definition to avoid going to the database
		_dao.metaClass.setUpSession = { -> container }

		_dao.authoritiesMethodName = 'getRoles'
		user.getRoles = { -> ['role1'] }
		_dao.passwordFieldName = 'password'
		user.password = 'passw0rd'
		_dao.enabledFieldName = 'enabled'
		user.enabled = true

		_dao.authenticateService = [securityConfig: [security: [useNtlm: false]]]

		UserDetails details = _dao.loadUserByUsername(username)
		assertNotNull details

		EasyMock.verify session, query
	}

	/**
	 * Test loadUserByUsername() when NTLM is enabled.
	 */
	void testLoadUserByUsernameNTLM() {

		String username = 'a_USER'
		def user = new Expando()

		Session session = EasyMock.createMock(Session)
		Query query = EasyMock.createMock(Query)
		EasyMock.expect(session.createQuery('from User where username=:username')).andReturn(query)
		EasyMock.expect(query.setString('username', username.toLowerCase())).andReturn(query)
		EasyMock.expect(query.setCacheable(true)).andReturn(query)
		EasyMock.expect(query.list()).andReturn([user])

		EasyMock.replay session, query

		def container = new GrailsWebApplicationObjectSupport.SessionContainer(session, true)

		// replace definition to avoid going to the database
		_dao.metaClass.setUpSession = { -> container }

		_dao.authoritiesMethodName = 'getRoles'
		user.getRoles = { -> ['role1'] }
		_dao.passwordFieldName = 'password'
		user.password = 'passw0rd'
		_dao.enabledFieldName = 'enabled'
		user.enabled = true

		_dao.authenticateService = [securityConfig: [security: [useNtlm: true]]]

		UserDetails details = _dao.loadUserByUsername(username)
		assertNotNull details

		EasyMock.verify session, query
	}

	/**
	 * Test createRolesByAuthoritiesMethod().
	 */
	void testCreateRolesByAuthoritiesMethod() {
		_dao.authoritiesMethodName = 'getRoles'
		def user = new Expando()
		user.getRoles = { -> ['role1', 'role2'] }

		def authorities = _dao.createRolesByAuthoritiesMethod(user, 'foo')
		assertEquals 2, authorities.size()

		def roleNames = authorities.collect { it.authority }
		assertTrue roleNames.contains('role1')
		assertTrue roleNames.contains('role2')
	}

	/**
	 * Test createRolesByRelationalAuthorities().
	 */
	void testCreateRolesByRelationalAuthorities() {
		_dao.relationalAuthoritiesField = 'roles'
		_dao.authorityFieldName = 'auth'

		def user = new Expando()
		user.roles = [[auth: 'role1'], [auth: 'role2']]

		def authorities = _dao.createRolesByRelationalAuthorities(user, 'foo')
		assertEquals 2, authorities.size()
		assertEquals 'role1', authorities[0].authority
		assertEquals 'role2', authorities[1].authority
	}

	/**
	 * {@inheritDoc}
	 * @see junit.framework.TestCase#tearDown()
	 */
	@Override
	protected void tearDown() {
		super.tearDown()
		removeMetaClassMethods GrailsDaoImpl
	}
}
