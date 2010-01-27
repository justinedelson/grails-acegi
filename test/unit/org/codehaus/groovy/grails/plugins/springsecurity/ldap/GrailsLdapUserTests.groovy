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
package org.codehaus.groovy.grails.plugins.springsecurity.ldap

import javax.naming.directory.Attributes

import org.springframework.security.GrantedAuthority
import org.springframework.security.GrantedAuthorityImpl
import org.springframework.security.userdetails.ldap.LdapUserDetails

/**
 * Unit tests for GrailsLdapUser.
 *
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
class GrailsLdapUserTests extends GroovyTestCase {

	private String dn = 'dn'
	private GrantedAuthority[] authorities =
		[new GrantedAuthorityImpl('role1'), new GrantedAuthorityImpl('role2')] as GrantedAuthority[]
	private String password = 'passw0rd'
	private String username = 'username'
	private boolean accountNonExpired = true
	private boolean accountNonLocked = false
	private boolean credentialsNonExpired = true
	private boolean enabled = false

	/**
	 * Test the copy constructor.
	 */
	void testCopyConstructor() {

		LdapUserDetails details = new TestLdapUserDetails(
			dn: dn, authorities: authorities, password: password,
			username: username, accountNonExpired: accountNonExpired,
			accountNonLocked: accountNonLocked,
			credentialsNonExpired: credentialsNonExpired, enabled: enabled)

		def domainClass = new Expando()
		GrailsLdapUser user = new GrailsLdapUser(details, domainClass, null)

		assertEquals dn, user.dn
		assertArrayEquals authorities, user.authorities
		assertEquals password, user.password
		assertEquals username, user.username
		assertEquals accountNonExpired, user.accountNonExpired
		assertEquals accountNonLocked, user.accountNonLocked
		assertEquals credentialsNonExpired, user.credentialsNonExpired
		assertEquals enabled, user.enabled
		assertEquals domainClass, user.domainClass
	}

	/**
	 * Test the full constructor.
	 */
	void testConstructor() {

		def domainClass = new Expando()
		GrailsLdapUser user = new GrailsLdapUser(username, password, enabled,
				accountNonExpired, credentialsNonExpired,
				accountNonLocked, authorities,
				null, dn, domainClass)

		assertEquals dn, user.dn
		assertArrayEquals authorities, user.authorities
		assertEquals password, user.password
		assertEquals username, user.username
		assertEquals accountNonExpired, user.accountNonExpired
		assertEquals accountNonLocked, user.accountNonLocked
		assertEquals credentialsNonExpired, user.credentialsNonExpired
		assertEquals enabled, user.enabled
		assertEquals domainClass, user.domainClass
	}
}

class TestLdapUserDetails implements LdapUserDetails {
	Attributes attributes
	String dn
	GrantedAuthority[] authorities
	String password
	String username

	// groovy 1.5.6 weirdness
	private boolean _enabled
	boolean isEnabled() {
		return _enabled
	}
	void setEnabled(boolean enabled) {
		_enabled = enabled
	}

	private boolean _credentialsNonExpired
	boolean isCredentialsNonExpired() {
		return _credentialsNonExpired
	}
	void setCredentialsNonExpired(boolean credentialsNonExpired) {
		_credentialsNonExpired = credentialsNonExpired
	}

	private boolean _accountNonExpired
	boolean isAccountNonExpired() {
		return _accountNonExpired
	}
	void setAccountNonExpired(boolean accountNonExpired) {
		_accountNonExpired = accountNonExpired
	}

	private boolean _accountNonLocked
	boolean isAccountNonLocked() {
		return _accountNonLocked
	}
	void setAccountNonLocked(boolean accountNonLocked) {
		_accountNonLocked = accountNonLocked
	}
}
