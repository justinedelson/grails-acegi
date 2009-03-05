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
package org.codehaus.groovy.grails.plugins.springsecurity.kerberos

import java.security.Security
import javax.security.auth.login.AppConfigurationEntry
import javax.security.auth.login.Configuration

import org.codehaus.groovy.grails.plugins.springsecurity.AbstractSecurityTest
import org.codehaus.groovy.grails.plugins.springsecurity.GrailsDaoImpl
import org.codehaus.groovy.grails.plugins.springsecurity.GrailsUserImpl

import org.springframework.security.Authentication
import org.springframework.security.AuthenticationException
import org.springframework.security.GrantedAuthority
import org.springframework.security.GrantedAuthorityImpl
import org.springframework.security.providers.jaas.JaasAuthenticationProvider
import org.springframework.security.providers.jaas.JaasAuthenticationToken
import org.springframework.security.userdetails.UserDetails

/**
 * Unit tests for <code>GrailsKerberosAuthenticationProvider</code>.
 *
 * @author <a href='mailto:beckwithb@studentsonly.com'>Burt Beckwith</a>
 */
class GrailsKerberosAuthenticationProviderTests extends AbstractSecurityTest {

	private _provider = new GrailsKerberosAuthenticationProvider()

	void testMergeDatabaseRolesNoDetailsNoAuthorities() {
		def user = new GrailsUserImpl('username', 'password', true, true, true,
				true, [] as GrantedAuthority[], null)
		assertEquals 0, _provider.mergeDatabaseRoles(user, null).length
	}

	void testMergeDatabaseRoles() {
		GrantedAuthority[] authorities = [new GrantedAuthorityImpl('role1'), new GrantedAuthorityImpl('role2')]
		GrantedAuthority[] detailAuthorities = [new GrantedAuthorityImpl('role3'), new GrantedAuthorityImpl('role4')]
		def user = new GrailsUserImpl('username', 'password', true, true, true,
				true, detailAuthorities, null)
		assertEquals 4, _provider.mergeDatabaseRoles(user, authorities).length
	}

	void testAuthenticate() {

		Security.setProperty('login.configuration.provider', MockConfiguration.name)

		String username = 'username'
		String password = 'password'
		GrantedAuthority[] roles = [new GrantedAuthorityImpl('role1'), new GrantedAuthorityImpl('role2')]
		JaasAuthenticationToken authentication = new JaasAuthenticationToken(username, password, roles, null)

		_provider.userDetailsService = new TestGrailsDaoImpl()
		_provider.retrieveDatabaseRoles = true

		def jaasToken = _provider.authenticate(authentication)

		assertTrue jaasToken.authenticated
		assertEquals username, jaasToken.principal.username
		assertEquals password, jaasToken.credentials
		assertEquals 4, jaasToken.authorities.length
	}

	/**
	 * {@inheritDoc}
	 * @see junit.framework.TestCase#tearDown()
	 */
	@Override
	protected void tearDown() {
		super.tearDown()
		removeMetaClassMethods JaasAuthenticationProvider
	}
}

class TestGrailsDaoImpl extends GrailsDaoImpl {
	UserDetails loadUserByUsername(String username, boolean loadRoles) {
		GrantedAuthority[] authorities = [new GrantedAuthorityImpl('role3'), new GrantedAuthorityImpl('role4')]
		return new GrailsUserImpl('username', 'password', true, true, true, true,
				authorities, null)
	}
}

class MockConfiguration extends Configuration {

	@Override
	AppConfigurationEntry[] getAppConfigurationEntry(String name) {
		return [new AppConfigurationEntry(MockLoginModule.name,
				AppConfigurationEntry.LoginModuleControlFlag.REQUIRED,
				new HashMap<String, Object>())] as AppConfigurationEntry[]
	}
}
