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

import org.codehaus.groovy.grails.plugins.springsecurity.AbstractSecurityTest

import test.TestRequestmap

/**
 * Integration tests for AuthenticateService.
 *
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
class AuthenticateServiceIntegrationTests extends AbstractSecurityTest {

	def authenticateService

	/**
	 * Test findRequestmapsByRole.
	 */
	void testFindRequestmapsByRole() {

		new TestRequestmap(url: '/admin/role/**', configAttribute: 'ROLE_ADMIN').save()
		new TestRequestmap(url: '/admin/person/**', configAttribute: 'ROLE_ADMIN,ROLE_FOO').save()
		new TestRequestmap(url: '/admin/foo/**', configAttribute: 'ROLE_BAR,ROLE_ADMIN,ROLE_FOO').save()
		new TestRequestmap(url: '/admin/super/**', configAttribute: 'ROLE_SUPERUSER').save()
		new TestRequestmap(url: '/user/**', configAttribute: 'ROLE_USER').save(flush: true)

		def conf = [requestMapClass: 'test.TestRequestmap',
		            requestMapConfigAttributeField: 'configAttribute']
		def results = authenticateService.findRequestmapsByRole('ROLE_ADMIN', TestRequestmap, conf)
		assertEquals 3, results.size()
		assertEquals(['/admin/role/**', '/admin/person/**', '/admin/foo/**'] as Set, results*.url as Set)
	}
}
