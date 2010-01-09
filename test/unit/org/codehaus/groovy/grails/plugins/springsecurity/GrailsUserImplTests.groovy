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
import org.springframework.security.GrantedAuthority
import org.springframework.security.GrantedAuthorityImpl

/**
 * Unit tests for GrailsUserImpl.
 *
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
class GrailsUserImplTests extends GroovyTestCase {

	/**
	 * Simple test of the constructor.
	 */
	void testConstructor() {

		String username = 'the_username'
		String password = 'the_password'
		boolean enabled = true
		boolean accountNonExpired = false
		boolean credentialsNonExpired = true
		boolean accountNonLocked = false
		GrantedAuthority[] authorities = [
			new GrantedAuthorityImpl('role1'),
			new GrantedAuthorityImpl('role2'),
			new GrantedAuthorityImpl('role3')] as GrantedAuthority[]
		def user = EasyMock.createMock(GroovyObject)

		GrailsUserImpl grailsUser = new GrailsUserImpl(username, password, enabled, accountNonExpired,
				credentialsNonExpired, accountNonLocked, authorities, user)

		assertEquals username, grailsUser.username
		assertEquals password, grailsUser.password
		assertEquals enabled, grailsUser.enabled
		assertEquals accountNonExpired, grailsUser.accountNonExpired
		assertEquals credentialsNonExpired, grailsUser.credentialsNonExpired
		assertEquals accountNonLocked, grailsUser.accountNonLocked
		assertArrayEquals authorities, grailsUser.authorities
		assertEquals user, grailsUser.domainClass
	}
}
