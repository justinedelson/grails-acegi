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

import org.grails.plugins.springsecurity.test.TestingAuthenticationToken

import org.springframework.security.Authentication
import org.springframework.security.GrantedAuthority
import org.springframework.security.context.SecurityContextHolder as SCH

/**
 * Abstract base class for security unit tests.
 *
 * @author <a href='mailto:beckwithb@studentsonly.com'>Burt Beckwith</a>
 */
abstract class AbstractSecurityTest extends GroovyTestCase {

	/**
	 * {@inheritDoc}
	 * @see junit.framework.TestCase#tearDown()
	 */
	@Override
	protected void tearDown() {
		super.tearDown()
		SCH.context.authentication = null
	}

	/**
	 * Register a currently authenticated user.
	 * @return  the authentication
	 */
	protected Authentication authenticate() {
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
	protected Authentication authenticate(Object principal, Object credentials, GrantedAuthority[] authorities) {
		Authentication authentication = new TestingAuthenticationToken(principal, credentials, authorities)
		authentication.authenticated = true
		SCH.context.authentication = authentication
		return authentication
	}

	/**
	 * Remove overridden/added metaclass methods between tests.
	 * @param classes  the classes to clean up
	 */
	protected void removeMetaClassMethods(Class<?>... classes) {
		classes.each { clazz ->
			def emc = new ExpandoMetaClass(clazz, true, true)
			emc.initialize()
			GroovySystem.metaClassRegistry.setMetaClass(clazz, emc)
		}
	}

	protected void fixMetaClass(instance) {
		instance.class.metaClass.class.simpleName
		ExpandoMetaClass.enableGlobally()
		instance.metaClass = null
	}
}
