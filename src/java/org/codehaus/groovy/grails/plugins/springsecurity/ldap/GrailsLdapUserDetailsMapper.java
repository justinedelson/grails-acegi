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
package org.codehaus.groovy.grails.plugins.springsecurity.ldap;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.codehaus.groovy.grails.plugins.springsecurity.GrailsDaoImpl;
import org.codehaus.groovy.grails.plugins.springsecurity.GrailsUser;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.security.GrantedAuthority;
import org.springframework.security.userdetails.UserDetails;
import org.springframework.security.userdetails.ldap.LdapUserDetails;
import org.springframework.security.userdetails.ldap.LdapUserDetailsMapper;
import org.springframework.util.Assert;

/**
 * Extends the default to return a {@link GrailsLdapUser} implementing
 * both {@link GrailsUser} and {@link LdapUserDetails}.
 *
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
public class GrailsLdapUserDetailsMapper extends LdapUserDetailsMapper implements InitializingBean {

	private GrailsDaoImpl _userDetailsService;
	private Boolean _usePassword;
	private Boolean _retrieveDatabaseRoles;

	/**
	 * {@inheritDoc}
	 * @see org.springframework.security.userdetails.ldap.LdapUserDetailsMapper#mapUserFromContext(
	 * 	org.springframework.ldap.core.DirContextOperations, java.lang.String,
	 * 	org.springframework.security.GrantedAuthority[])
	 */
	@SuppressWarnings("deprecation")
	@Override
	public UserDetails mapUserFromContext(final DirContextOperations ctx, final String username,
			GrantedAuthority[] authorities) {

		GrailsUser dbDetails = (GrailsUser)_userDetailsService.loadUserByUsername(username, _retrieveDatabaseRoles);
		authorities = mergeDatabaseRoles(dbDetails, authorities);

		LdapUserDetails ldapDetails = (LdapUserDetails)super.mapUserFromContext(ctx, username, authorities);
		if (_usePassword) {
			return new GrailsLdapUser(ldapDetails, dbDetails.getDomainClass());
		}

		// use a dummy password to avoid an exception from the User base class
		return new GrailsLdapUser(ldapDetails.getUsername(), "not_used", ldapDetails.isEnabled(),
				ldapDetails.isAccountNonExpired(), ldapDetails.isCredentialsNonExpired(),
				ldapDetails.isAccountNonLocked(), ldapDetails.getAuthorities(),
				ldapDetails.getAttributes(), ldapDetails.getDn(), dbDetails.getDomainClass());
	}

	private GrantedAuthority[] mergeDatabaseRoles(final UserDetails details, final GrantedAuthority[] authorities) {
		List<GrantedAuthority> merged = new ArrayList<GrantedAuthority>();
		if (authorities != null && authorities.length > 0) {
			merged.addAll(Arrays.asList(authorities));
		}

		if (details.getAuthorities() != null && details.getAuthorities().length > 0) {
			merged.addAll(Arrays.asList(details.getAuthorities()));
		}

		return merged.toArray(new GrantedAuthority[merged.size()]);
	}

	/**
	 * Dependency injection for the user details service.
	 * @param service  the service
	 */
	public void setUserDetailsService(final GrailsDaoImpl service) {
		_userDetailsService = service;
	}

	/**
	 * Dependency injection for whether to use passwords retrieved from LDAP.
	 * @param use  if <code>true</code> then uses the retrieved password, other wise sets dummy value
	 */
	public void setUsePassword(final boolean use) {
		_usePassword = use;
	}

	/**
	 * Dependency injection for whether to retrieve roles from the database in addition to LDAP.
	 * @param retrieve  if <code>true</code> then load roles from database also
	 */
	public void setRetrieveDatabaseRoles(final boolean retrieve) {
		_retrieveDatabaseRoles = retrieve;
	}

	/**
	 * {@inheritDoc}
	 * @see org.springframework.beans.factory.InitializingBean#afterPropertiesSet()
	 */
	public void afterPropertiesSet() {
		Assert.notNull(_userDetailsService, "userDetailsService must be specified");
		Assert.notNull(_usePassword, "usePassword must be specified");
		Assert.notNull(_retrieveDatabaseRoles, "retrieveDatabaseRoles must be specified");
	}
}
