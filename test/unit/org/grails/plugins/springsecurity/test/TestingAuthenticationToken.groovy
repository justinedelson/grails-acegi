package org.grails.plugins.springsecurity.test

import org.springframework.security.GrantedAuthority
import org.springframework.security.providers.AbstractAuthenticationToken
import org.springframework.security.util.AuthorityUtils

/**
 * Replacement for the version from Spring Security that was moved from
 * the source tree to the test tree.
 *
 * @author <a href='mailto:beckwithb@studentsonly.com'>Burt Beckwith</a>
 */
class TestingAuthenticationToken extends AbstractAuthenticationToken {

	private static final long serialVersionUID = 1L

	private final def _credentials
	private final def _principal

	TestingAuthenticationToken() {
		this(null, null, null)
	}

	TestingAuthenticationToken(Object principal, Object credentials, GrantedAuthority[] authorities) {
		super(authorities)
		_credentials = credentials
		_principal = principal
	}

	Object getCredentials() {
		return _credentials
	}

	Object getPrincipal() {
		return _principal
	}
}
