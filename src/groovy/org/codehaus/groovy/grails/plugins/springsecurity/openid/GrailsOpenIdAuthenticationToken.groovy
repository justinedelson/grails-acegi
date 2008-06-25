package org.codehaus.groovy.grails.plugins.springsecurity.openid

import org.springframework.security.GrantedAuthorityimport org.springframework.security.providers.openid.OpenIDAuthenticationStatusimport org.springframework.security.providers.openid.OpenIDAuthenticationToken
import org.springframework.security.userdetails.UserDetails
/**
 * TODO  javadoc
 *
 * @author Burt
 */
class GrailsOpenIdAuthenticationToken extends OpenIDAuthenticationToken {

	private UserDetails _userDetails

	GrailsOpenIdAuthenticationToken(
			UserDetails userDetails,
			OpenIDAuthenticationStatus status,
			String identityUrl) {
		super(userDetails.authorities, status, identityUrl)
		_userDetails = userDetails
	}

	@Override
	Object getPrincipal() {
		return _userDetails
	}
}
