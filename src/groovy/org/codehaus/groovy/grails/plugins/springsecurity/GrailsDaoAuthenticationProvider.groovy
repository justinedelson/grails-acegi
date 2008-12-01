package org.codehaus.groovy.grails.plugins.springsecurity

import org.springframework.security.AuthenticationException
import org.springframework.security.providers.UsernamePasswordAuthenticationToken
import org.springframework.security.providers.dao.DaoAuthenticationProvider
import org.springframework.security.ui.ntlm.NtlmUsernamePasswordAuthenticationToken
import org.springframework.security.userdetails.UserDetails

/**
 * TODO  javadoc
 *
 * @author <a href='mailto:beckwithb@studentsonly.com'>Burt Beckwith</a>
 */
class GrailsDaoAuthenticationProvider extends DaoAuthenticationProvider {

	@Override
	protected void additionalAuthenticationChecks(UserDetails userDetails,
            UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {

        // don't check password in case of NTLM authentication
        if (!(authentication instanceof NtlmUsernamePasswordAuthenticationToken)) {
            super.additionalAuthenticationChecks(userDetails, authentication)
        }
    }
}
