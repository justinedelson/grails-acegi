package org.codehaus.groovy.grails.plugins.springsecurity.openid

import org.springframework.security.Authenticationimport org.springframework.security.AuthenticationExceptionimport org.springframework.security.AuthenticationServiceException
import org.springframework.security.BadCredentialsException
import org.springframework.security.providers.openid.AuthenticationCancelledException
import org.springframework.security.providers.openid.OpenIDAuthenticationStatusimport org.springframework.security.providers.openid.OpenIDAuthenticationProvider
import org.springframework.security.providers.openid.OpenIDAuthenticationToken
import org.springframework.security.userdetails.UserDetails
import org.springframework.security.userdetails.UserDetailsService
/**
 * Subclass that returns a <code>GrailsOpenIdAuthenticationToken</code>.
 *
 * @author <a href='mailto:beckwithb@studentsonly.com'>Burt Beckwith</a>
 */
class GrailsOpenIdAuthenticationProvider extends OpenIDAuthenticationProvider {

	private def _userDetailsService

	/**
	 * {@inheritDoc}
	 * @see org.springframework.security.providers.openid.OpenIDAuthenticationProvider#authenticate(
	 * 	org.springframework.security.Authentication)
	 */
	@Override
	Authentication authenticate(Authentication authentication) throws AuthenticationException {

		if (!supports(authentication.getClass())) {
			return null
		}

		if (authentication instanceof OpenIDAuthenticationToken) {
			OpenIDAuthenticationToken response = (OpenIDAuthenticationToken) authentication
			OpenIDAuthenticationStatus status = response.status

			// handle the various possibilites
			if (status == OpenIDAuthenticationStatus.SUCCESS) {
				// Lookup user details
				UserDetails userDetails = _userDetailsService.loadUserByUsername(response.identityUrl)
				return new GrailsOpenIdAuthenticationToken(userDetails, response.status, response.identityUrl)
			}

			if (status == OpenIDAuthenticationStatus.CANCELLED) {
				throw new AuthenticationCancelledException("Log in cancelled")
			}

			if (status == OpenIDAuthenticationStatus.ERROR) {
				throw new AuthenticationServiceException("Error message from server: $response.message")
			}

			if (status == OpenIDAuthenticationStatus.FAILURE) {
				throw new BadCredentialsException("Log in failed - identity could not be verified")
			}

			if (status == OpenIDAuthenticationStatus.SETUP_NEEDED) {
				throw new AuthenticationServiceException(
						"The server responded setup was needed, which shouldn't happen")
			}

			throw new AuthenticationServiceException("Unrecognized return value $status")
		}

		return null
	}

	/**
	 * {@inheritDoc}
	 * @see org.springframework.security.providers.openid.OpenIDAuthenticationProvider#setUserDetailsService(
	 * 	org.springframework.security.userdetails.UserDetailsService)
	 */
	@Override
	void setUserDetailsService(UserDetailsService userDetailsService) {
		_userDetailsService = userDetailsService
		super.setUserDetailsService(userDetailsService)
	}
}
