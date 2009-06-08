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

import org.springframework.security.GrantedAuthority
import org.springframework.security.GrantedAuthorityImpl

/**
 * Unit tests for <code>NullSaltSource</code>.
 *
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
class NullSaltSourceTests extends AbstractSecurityTest {

	void testGetSalt() {
		def authorities = [new GrantedAuthorityImpl('ROLE_USER')] as GrantedAuthority[]
		def user = new GrailsUserImpl('username', 'password', true, true, true, true,
				authorities, null)
		assertNull new NullSaltSource().getSalt(user)
	}
}
