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

import java.lang.reflect.Modifier

import org.grails.plugins.springsecurity.test.TestingAuthenticationToken

import org.springframework.security.Authentication
import org.springframework.security.GrantedAuthority
import org.springframework.security.GrantedAuthorityImpl;
import org.springframework.security.context.SecurityContextHolder as SCH

/**
 * Utility methods for security unit tests.
 *
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
class SecurityTestUtils extends GroovyTestCase {

	/**
	 * Register a currently authenticated user.
	 * @return  the authentication
	 */
	static Authentication authenticate() {
		return authenticate(null, null, null)
	}

	/**
	 * Register a currently authenticated user.
	 *
	 * @param principal  the principal
	 * @param credentials  the password
	 * @param authorities  the roles
	 * @return  the authentication
	 */
	static Authentication authenticate(Object principal, Object credentials, GrantedAuthority[] authorities) {
		Authentication authentication = new TestingAuthenticationToken(principal, credentials, authorities)
		authentication.authenticated = true
		SCH.context.authentication = authentication
		return authentication
	}

	static Authentication authenticate(roleNames) {
		def authorities = roleNames.collect { new GrantedAuthorityImpl(it) }
		return authenticate(null, null, authorities as GrantedAuthority[])
	}

	/**
	 * De-register the currently authenticated user.
	 */
	static void logout() {
		SCH.clearContext()
	}

	static void testPrivateConstructor(Class clazz) {
		assertEquals 1, clazz.declaredConstructors.length
		def constructor = clazz.getDeclaredConstructor()
		assertTrue Modifier.isPrivate(constructor.modifiers)
		assertFalse constructor.accessible
		constructor.accessible = true
		constructor.newInstance()
	}
}
