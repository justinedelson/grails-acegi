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
package org.codehaus.groovy.grails.plugins.springsecurity.ldap

import org.easymock.EasyMock
import org.springframework.ldap.core.DirContextOperations
import org.springframework.security.GrantedAuthority
import org.springframework.security.GrantedAuthorityImpl
import org.springframework.security.userdetails.UserDetails

import org.codehaus.groovy.grails.plugins.springsecurity.GrailsDaoImpl
import org.codehaus.groovy.grails.plugins.springsecurity.GrailsUserImplclass GrailsLdapUserDetailsMapperTests extends GroovyTestCase {

	private _mapper = new GrailsLdapUserDetailsMapper()

	void testAfterPropertiesSet() {

		String message = shouldFail(IllegalArgumentException) {
			_mapper.afterPropertiesSet()
		}
		assertEquals 'userDetailsService must be specified', message

		_mapper.userDetailsService = new GrailsDaoImpl()

		message = shouldFail(IllegalArgumentException) {
			_mapper.afterPropertiesSet()
		}
		assertEquals 'usePassword must be specified', message

		_mapper.usePassword = true
		message = shouldFail(IllegalArgumentException) {
			_mapper.afterPropertiesSet()
		}
		assertEquals 'retrieveDatabaseRoles must be specified', message

		_mapper.retrieveDatabaseRoles = true
		message = shouldFail(IllegalArgumentException) {
			_mapper.afterPropertiesSet()
		}
		assertEquals 'retrieveUserDomainObject must be specified', message

		_mapper.retrieveUserDomainObject = true
		_mapper.afterPropertiesSet()
	}

	void testMergeDatabaseRoles() {
		GrantedAuthority[] dbAuthorities = [new GrantedAuthorityImpl('ROLE_ADMIN')]
		def details = new GrailsUserImpl('username', 'password', true, true, true, true,
				dbAuthorities, null)

		GrantedAuthority[] authorities = [new GrantedAuthorityImpl('ROLE_FOO')]
		def merged = _mapper.mergeDatabaseRoles(details, authorities)

		assertEquals 2, merged.size()
	}

	void testMapUserFromContextUsePasswordTrue() {
		_mapper.retrieveDatabaseRoles = true
		_mapper.retrieveUserDomainObject = true
		_mapper.usePassword = true
		_mapper.userDetailsService = new TestGrailsDaoImpl()

		String username = 'username'
		String password = 'passw0rd'
		String dn = 'dn'
		def ctx = EasyMock.createMock(DirContextOperations)
		EasyMock.expect(ctx.getNameInNamespace()).andReturn(dn)
		EasyMock.expect(ctx.getObjectAttribute('userPassword')).andReturn(password)
		EasyMock.replay ctx

		def user = _mapper.mapUserFromContext(ctx, username)

		assertEquals password, user.password
		assertEquals username, user.username
		assertEquals 1, user.authorities.length
		assertEquals 'ROLE_ADMIN', user.authorities[0].authority

		EasyMock.verify ctx
	}

	void testMapUserFromContextUsePasswordFalse() {
		_mapper.retrieveDatabaseRoles = true
		_mapper.retrieveUserDomainObject = true
		_mapper.usePassword = false
		_mapper.userDetailsService = new TestGrailsDaoImpl()

		String username = 'username'
		String dn = 'dn'
		def ctx = EasyMock.createMock(DirContextOperations)
		EasyMock.expect(ctx.getNameInNamespace()).andReturn(dn)
		EasyMock.expect(ctx.getObjectAttribute('userPassword')).andReturn(null)
		EasyMock.replay ctx

		def user = _mapper.mapUserFromContext(ctx, username)

		assertEquals 'not_used', user.password
		assertEquals username, user.username
		assertEquals 1, user.authorities.length
		assertEquals 'ROLE_ADMIN', user.authorities[0].authority

		EasyMock.verify ctx
	}
}

class TestGrailsDaoImpl extends GrailsDaoImpl {
	UserDetails loadUserByUsername(String username, boolean loadRoles) {
		GrantedAuthority[] authorities = [new GrantedAuthorityImpl('ROLE_ADMIN')]
		return new GrailsUserImpl('username', 'password', true, true, true, true,
				authorities, null)
	}
}
