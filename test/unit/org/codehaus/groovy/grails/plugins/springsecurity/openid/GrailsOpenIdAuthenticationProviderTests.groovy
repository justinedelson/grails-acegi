package org.codehaus.groovy.grails.plugins.springsecurity.openid

import org.codehaus.groovy.grails.plugins.springsecurity.AbstractSecurityTest
import org.codehaus.groovy.grails.plugins.springsecurity.GrailsUserImpl
import org.springframework.security.AuthenticationServiceException
import org.springframework.security.BadCredentialsException
import org.springframework.security.GrantedAuthority
import org.springframework.security.GrantedAuthorityImpl
import org.springframework.security.providers.TestingAuthenticationTokenimport org.springframework.security.providers.openid.AuthenticationCancelledException
import org.springframework.security.providers.openid.OpenIDAuthenticationStatus
import org.springframework.security.providers.openid.OpenIDAuthenticationToken
/**
 * Unit tests for <code>GrailsOpenIdAuthenticationProvider</code>.
 *
 * @author <a href='mailto:beckwithb@studentsonly.com'>Burt Beckwith</a>
 */
class GrailsOpenIdAuthenticationProviderTests extends AbstractSecurityTest {

	private final GrailsOpenIdAuthenticationProvider _provider = new GrailsOpenIdAuthenticationProvider()

	void testAuthenticateNotSupported() {

		def authentication = new TestingAuthenticationToken(null, null, null)
		assertNull _provider.authenticate(authentication)
	}

	void testAuthenticateStatusCancelled() {
		def authentication = new OpenIDAuthenticationToken(OpenIDAuthenticationStatus.CANCELLED, null, null)
		shouldFail(AuthenticationCancelledException) {
			_provider.authenticate(authentication)
		}
	}

	void testAuthenticateStatusError() {
		def authentication = new OpenIDAuthenticationToken(OpenIDAuthenticationStatus.ERROR, null, null)
		shouldFail(AuthenticationServiceException) {
			_provider.authenticate(authentication)
		}
	}

	void testAuthenticateStatusFailure() {
		def authentication = new OpenIDAuthenticationToken(OpenIDAuthenticationStatus.FAILURE, null, null)
		shouldFail(BadCredentialsException) {
			_provider.authenticate(authentication)
		}
	}

	void testAuthenticateStatusSetupNeeded() {
		def authentication = new OpenIDAuthenticationToken(OpenIDAuthenticationStatus.SETUP_NEEDED, null, null)
		shouldFail(AuthenticationServiceException) {
			_provider.authenticate(authentication)
		}
	}

	void testAuthenticateUnexpectedStatus() {
		def authentication = new OpenIDAuthenticationToken(new OpenIDAuthenticationStatus('foo'), null, null)
		try {
			_provider.authenticate(authentication)
			fail 'should have failed with AuthenticationServiceException'
		}
		catch (AuthenticationServiceException e) {
			assertEquals "Unrecognized return value foo", e.message
		}
	}

	void testAuthenticateSuccess() {
		String url = 'the_url'
		def authentication = new OpenIDAuthenticationToken(OpenIDAuthenticationStatus.SUCCESS, url, null)
		def roles = [new GrantedAuthorityImpl('role1')] as GrantedAuthority[]
		def details = new GrailsUserImpl('username', 'password', true, true, true, true, roles, null)
		_provider.@_userDetailsService = [loadUserByUsername: { identityUrl -> details }]

		def token = _provider.authenticate(authentication)
		assertNotNull token

		assertSame details, token.principal
		assertEquals url, token.identityUrl
		assertEquals OpenIDAuthenticationStatus.SUCCESS, token.getStatus()
	}
}
