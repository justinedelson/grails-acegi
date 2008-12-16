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

import org.codehaus.groovy.grails.plugins.springsecurity.ldap.GrailsLdapUser

import org.springframework.ldap.core.DirContextOperations
import org.springframework.security.GrantedAuthority
import org.springframework.security.userdetails.UserDetails
import org.springframework.security.userdetails.ldap.LdapUserDetails
import org.springframework.security.userdetails.ldap.LdapUserDetailsMapper

/**
 * Extends the default to return a <code>GrailsLdapUser</code> implementing
 * both <code>GrailsUser</code> and <code>LdapUserDetails</code>.
 *
 * @author <a href='mailto:beckwithb@studentsonly.com'>Burt Beckwith</a>
 */
class GrailsLdapUserDetailsMapper extends LdapUserDetailsMapper {

	/**
	 * Dependency injection for the user service.
	 */
	def userDetailsService

	/**
	 * Dependency injection for the authentication service.
	 */
	def authenticateService

	/**
	 * {@inheritDoc}
	 * @see org.springframework.security.userdetails.ldap.LdapUserDetailsMapper#mapUserFromContext(
	 * 	org.springframework.ldap.core.DirContextOperations, java.lang.String,
	 * 	org.springframework.security.GrantedAuthority[])
	 */
	@Override
	UserDetails mapUserFromContext(DirContextOperations ctx, String username, GrantedAuthority[] authorities) {

		boolean retrieveDatabaseRoles = authenticateService.securityConfig.security.ldapRetrieveDatabaseRoles
		def dbDetails = userDetailsService.loadUserByUsername(username, retrieveDatabaseRoles)
		authorities = mergeDatabaseRoles(dbDetails, authorities)

		LdapUserDetails ldapDetails = (LdapUserDetails)super.mapUserFromContext(ctx, username, authorities)
		return new GrailsLdapUser(ldapDetails, dbDetails.domainClass)
	}

	private GrantedAuthority[] mergeDatabaseRoles(details, GrantedAuthority[] authorities) {
		def merged = []
		if (authorities) {
			merged.addAll(authorities as List)
		}

		if (details.authorities) {
			merged.addAll(details.authorities as List)
		}

		return merged as GrantedAuthority[]
	}
}
