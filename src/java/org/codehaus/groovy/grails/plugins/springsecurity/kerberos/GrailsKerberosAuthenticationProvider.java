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
package org.codehaus.groovy.grails.plugins.springsecurity.kerberos;

import java.util.ArrayList;
import java.util.List;

import org.codehaus.groovy.grails.plugins.springsecurity.GrailsDaoImpl;
import org.springframework.security.Authentication;
import org.springframework.security.AuthenticationException;
import org.springframework.security.GrantedAuthority;
import org.springframework.security.GrantedAuthorityImpl;
import org.springframework.security.providers.AuthenticationProvider;
import org.springframework.security.providers.jaas.JaasAuthenticationProvider;
import org.springframework.security.providers.jaas.JaasAuthenticationToken;
import org.springframework.security.userdetails.UserDetails;

/**
* Kerberos {@link AuthenticationProvider}.
*
* @author <a href='mailto:mmornati@byte-code.com'>Marco Mornati</a>
* @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
*/
public class GrailsKerberosAuthenticationProvider extends JaasAuthenticationProvider {

	private GrailsDaoImpl _userDetailsService;
	private boolean _retrieveDatabaseRoles;

	/**
	 * {@inheritDoc}
	 * @see org.springframework.security.providers.jaas.JaasAuthenticationProvider#authenticate(
	 * 	org.springframework.security.Authentication)
	 */
	@Override
	public Authentication authenticate(final Authentication auth) throws AuthenticationException {

		Authentication authToken = super.authenticate(auth);

		if (authToken instanceof JaasAuthenticationToken) {
			String username = (String)authToken.getPrincipal();
			UserDetails dbDetails = _userDetailsService.loadUserByUsername(username, _retrieveDatabaseRoles);
			GrantedAuthority[] authorities = mergeDatabaseRoles(dbDetails, authToken.getAuthorities());
			authToken = new JaasAuthenticationToken(dbDetails, authToken.getCredentials(),
					authorities, ((JaasAuthenticationToken)authToken).getLoginContext());
		}

		return authToken;
	}

	private GrantedAuthority[] mergeDatabaseRoles(final UserDetails details, final GrantedAuthority[] authorities) {
		List<GrantedAuthority> merged = new ArrayList<GrantedAuthority>();
		merge(merged, authorities);
		merge(merged, details.getAuthorities());
		return merged.toArray(new GrantedAuthorityImpl[merged.size()]);
	}

	private void merge(final List<GrantedAuthority> merged, final GrantedAuthority[] authorities) {
		if (authorities != null && authorities.length > 0) {
			for (GrantedAuthority authority : authorities) {
				merged.add(authority);
			}
		}
	}

	/**
	 * Dependency injection for the user details service.
	 * @param service  the service
	 */
	public void setUserDetailsService(final GrailsDaoImpl service) {
		_userDetailsService = service;
	}

	/**
	 * Dependency injection for whether to load roles from the database.
	 * @param retrieve  if <code>true</code> loads from database
	 */
	public void setRetrieveDatabaseRoles(final boolean retrieve) {
		_retrieveDatabaseRoles = retrieve;
	}
}
