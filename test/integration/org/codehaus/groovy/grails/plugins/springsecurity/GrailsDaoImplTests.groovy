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

import org.springframework.security.userdetails.UsernameNotFoundException

import test.TestRole
import test.TestUser

/**
 * Integration tests for GrailsDaoImpl.
 *
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
class GrailsDaoImplTests extends GroovyTestCase {

	private static final String ADMIN_ROLE_NAME = 'ROLE_ADMIN'
	private static final String SUPER_ADMIN_ROLE_NAME = 'ROLE_SUPERADMIN'

	private GrailsDaoImpl _dao
	private TestRole _adminRole
	private TestRole _superAdminRole

	def sessionFactory

	protected void setUp() {
		super.setUp()

		def config = AuthorizeTools.securityConfig.security

		_dao = new GrailsDaoImpl(sessionFactory: sessionFactory, usernameFieldName: config.userName,
				passwordFieldName: config.password, enabledFieldName: config.enabled,
				authorityFieldName: config.authorityField, loginUserDomainClass: config.loginUserDomainClass,
				relationalAuthoritiesField: config.relationalAuthorities,
				authoritiesMethodName: config.getAuthoritiesMethod)

		assertEquals 0, TestRole.count()
		_adminRole = new TestRole(description: 'admin', auth: ADMIN_ROLE_NAME).save()
		_superAdminRole = new TestRole(description: 'superadmin', auth: SUPER_ADMIN_ROLE_NAME).save()
		assertEquals 2, TestRole.count()
	}

	void testLoadUserByUsername_NotFound() {
		String message = shouldFail(UsernameNotFoundException) {
			_dao.loadUserByUsername 'not_a_user'
		}

		assertTrue message.contains('not found')
	}

	void testLoadUserByUsername_NoRoles() {

		String loginName = 'loginName'

		assertEquals 0, TestUser.count()
		new TestUser(loginName: loginName, passwrrd: 'password', enabld: true).save()
		assertEquals 1, TestUser.count()

		String message = shouldFail(UsernameNotFoundException) {
			_dao.loadUserByUsername loginName
		}

		assertEquals 'User has no GrantedAuthority', message
	}

	void testLoadUserByUsername() {

		String loginName = 'loginName'
		String password = 'password123'
		boolean enabled = true

		assertEquals 0, TestUser.count()
		def user = new TestUser(loginName: loginName, passwrrd: password, enabld: enabled).save()
		assertEquals 1, TestUser.count()

		_adminRole.addToPeople user
		_superAdminRole.addToPeople user

		def details = _dao.loadUserByUsername(loginName)
		assertNotNull details

		assertEquals password, details.password
		assertEquals loginName, details.username
		assertEquals enabled, details.enabled
		assertEquals enabled, details.accountNonExpired
		assertEquals enabled, details.accountNonLocked
		assertEquals enabled, details.credentialsNonExpired
		assertEquals([ADMIN_ROLE_NAME, SUPER_ADMIN_ROLE_NAME], details.authorities*.authority.sort())
	}

	void testLoadUserByUsername_SkipRoles() {

		String loginName = 'loginName'
		String password = 'password123'
		boolean enabled = true
		
		assertEquals 0, TestUser.count()
		def user = new TestUser(loginName: loginName, passwrrd: password, enabld: enabled).save()
		assertEquals 1, TestUser.count()
		
		_adminRole.addToPeople user
		_superAdminRole.addToPeople user
		
		def details = _dao.loadUserByUsername(loginName, false)
		assertNotNull details

		assertEquals password, details.password
		assertEquals loginName, details.username
		assertEquals enabled, details.enabled
		assertEquals enabled, details.accountNonExpired
		assertEquals enabled, details.accountNonLocked
		assertEquals enabled, details.credentialsNonExpired
		assertEquals 0, details.authorities.size()
	}
	
	void testLoadUserByUsername_CreateRolesByAuthoritiesMethod() {

		_dao.relationalAuthoritiesField = null
		_dao.authoritiesMethodName = 'getRoleNames'

		String loginName = 'loginName'
		String password = 'password123'
		boolean enabled = true
		
		assertEquals 0, TestUser.count()
		def user = new TestUser(loginName: loginName, passwrrd: password, enabld: enabled).save()
		assertEquals 1, TestUser.count()
		
		_adminRole.addToPeople user
		_superAdminRole.addToPeople user
		
		def details = _dao.loadUserByUsername(loginName)
		assertNotNull details
		
		assertEquals password, details.password
		assertEquals loginName, details.username
		assertEquals enabled, details.enabled
		assertEquals enabled, details.accountNonExpired
		assertEquals enabled, details.accountNonLocked
		assertEquals enabled, details.credentialsNonExpired
		assertEquals([ADMIN_ROLE_NAME, SUPER_ADMIN_ROLE_NAME], details.authorities*.authority.sort())
	}

	void testLoadUserByUsername_NTLM() {

		_dao.useNtlm = true
		String loginName = 'loginName'
		String password = 'password123'
		boolean enabled = true

		assertEquals 0, TestUser.count()
		def user = new TestUser(loginName: loginName.toLowerCase(), passwrrd: password, enabld: enabled).save()
		assertEquals 1, TestUser.count()

		_adminRole.addToPeople user
		_superAdminRole.addToPeople user

		assertNotNull _dao.loadUserByUsername(loginName)
		assertNotNull _dao.loadUserByUsername(loginName.toLowerCase())
		assertNotNull _dao.loadUserByUsername(loginName.toUpperCase())
	}
}
