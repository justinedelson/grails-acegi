package org.codehaus.groovy.grails.plugins.springsecurity.openid

import org.springframework.security.GrantedAuthorityimport org.springframework.security.providers.openid.OpenIDAuthenticationStatusimport org.springframework.security.providers.openid.OpenIDAuthenticationToken
import org.springframework.security.userdetails.UserDetails
/**
 * Subclass that holds the user domain instance.
 *
 * @author <a href='mailto:beckwithb@studentsonly.com'>Burt Beckwith</a>
 */
class GrailsOpenIdAuthenticationToken extends OpenIDAuthenticationToken {

	private UserDetails _userDetails

 	/**
 	 * Full constructor.
 	 * @param userDetails  the details
 	 * @param status  the status
 	 * @param identityUrl  the url
 	 */
	GrailsOpenIdAuthenticationToken(
			UserDetails userDetails,
			OpenIDAuthenticationStatus status,
			String identityUrl) {
		super(userDetails.authorities, status, identityUrl)
		_userDetails = userDetails
	}

 	/**
 	 * {@inheritDoc}
 	 * @see org.springframework.security.providers.openid.OpenIDAuthenticationToken#getPrincipal()
 	 */
	@Override
	Object getPrincipal() {
		return _userDetails
	}
}
