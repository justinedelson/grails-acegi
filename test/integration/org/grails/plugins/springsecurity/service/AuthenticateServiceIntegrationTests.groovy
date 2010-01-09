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

import test.TestRequestmap
import test.TestRole
import test.TestRole2

/**
 * Integration tests for AuthenticateService.
 *
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
class AuthenticateServiceIntegrationTests extends GroovyTestCase {

	def authenticateService
	def sessionFactory

	private oldSecurityConfig

	/**
	 * {@inheritDoc}
	 * @see junit.framework.TestCase#setUp()
	 */
	@Override
	protected void setUp() {
		super.setUp()
		oldSecurityConfig = authenticateService.@securityConfig
	}

	/**
	 * Test findRequestmapsByRole.
	 */
	void testFindRequestmapsByRole() {

		createTestRequestmaps()

		def conf = [requestMapClass: 'test.TestRequestmap',
		            requestMapConfigAttributeField: 'rolePattern']
		def results = authenticateService.findRequestmapsByRole('ROLE_ADMIN', TestRequestmap, conf)
		assertEquals 3, results.size()
		assertEquals(['/admin/role/**', '/admin/person/**', '/admin/foo/**'] as Set, results*.urlPattern as Set)
	}

	void testUpdateRole() {

		createTestRequestmaps()

		String description = 'description'
		String authority = 'ROLE_ADMIN'
		def role = new TestRole(description: description, auth: authority).save(flush: true)

		sessionFactory.currentSession.clear()

		role = TestRole.list()[0]
		assertEquals description, role.description
		assertEquals authority, role.auth

		String newDescription = 'new description'
		String newAuthority = ''
		assertFalse authenticateService.updateRole(role, [description: newDescription, auth: newAuthority])

		newAuthority = 'new authority'
		assertTrue authenticateService.updateRole(role, [description: newDescription, auth: newAuthority])
		assertEquals newDescription, role.description
		assertEquals newAuthority, role.auth
	}

	private void createTestRequestmaps() {
		new TestRequestmap(urlPattern: '/admin/role/**', rolePattern: 'ROLE_ADMIN').save()
		new TestRequestmap(urlPattern: '/admin/person/**', rolePattern: 'ROLE_ADMIN,ROLE_FOO').save()
		new TestRequestmap(urlPattern: '/admin/foo/**', rolePattern: 'ROLE_BAR,ROLE_ADMIN,ROLE_FOO').save()
		new TestRequestmap(urlPattern: '/admin/super/**', rolePattern: 'ROLE_SUPERUSER').save()
		new TestRequestmap(urlPattern: '/user/**', rolePattern: 'ROLE_USER').save(flush: true)
		assertEquals 5, TestRequestmap.count()
	}

	/**
	 * {@inheritDoc}
	 * @see junit.framework.TestCase#tearDown()
	 */
	@Override
	protected void tearDown() {
		super.tearDown()
		authenticateService.@securityConfig = oldSecurityConfig
	}
}
