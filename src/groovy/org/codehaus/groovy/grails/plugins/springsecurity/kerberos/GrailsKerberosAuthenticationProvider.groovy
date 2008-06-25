package org.codehaus.groovy.grails.plugins.springsecurity.kerberos

import org.springframework.security.Authentication
import org.springframework.security.AuthenticationException
import org.springframework.security.GrantedAuthority
import org.springframework.security.providers.jaas.JaasAuthenticationProvider
import org.springframework.security.providers.jaas.JaasAuthenticationToken

 /**
  * Kerberos AuthenticationProvider.
  *
  * @author <a href='mailto:mmornati@byte-code.com'>Marco Mornati</a>
  * @author <a href='mailto:beckwithb@studentsonly.com'>Burt Beckwith</a>
  */
class GrailsKerberosAuthenticationProvider extends JaasAuthenticationProvider {

	def authenticateService
	def userDetailsService

	/**
	 * {@inheritDoc}
	 * @see org.springframework.security.providers.jaas.JaasAuthenticationProvider#authenticate(
	 * 	org.springframework.security.Authentication)
	 */
	@Override
	Authentication authenticate(Authentication auth) throws AuthenticationException {

		Authentication authToken = super.authenticate(auth)

		if (authToken instanceof JaasAuthenticationToken) {
			String username = authToken.credentials
			boolean retrieveDatabaseRoles = authenticateService.securityConfig.security.kerberosRetrieveDatabaseRoles
			def dbDetails = userDetailsService.loadUserByUsername(username, retrieveDatabaseRoles)
			def authorities = mergeDatabaseRoles(dbDetails, authToken.authorities)
			dbDetails.authorities = authorities
			authToken = new JaasAuthenticationToken(
					dbDetails, authToken.credentials,
					dbDetails.authorities, authToken.loginContext);
		}

		return authToken
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
