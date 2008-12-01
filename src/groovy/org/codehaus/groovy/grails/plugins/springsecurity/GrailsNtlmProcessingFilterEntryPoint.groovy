package org.codehaus.groovy.grails.plugins.springsecurity

import org.springframework.security.AuthenticationException
import org.springframework.security.BadCredentialsException
import org.springframework.security.ui.ntlm.NtlmBaseException
import org.springframework.security.ui.ntlm.NtlmBeginHandshakeException
import org.springframework.security.ui.ntlm.NtlmProcessingFilter
import org.springframework.security.ui.ntlm.NtlmProcessingFilterEntryPoint

import javax.servlet.ServletException
import javax.servlet.ServletRequest
import javax.servlet.ServletResponse
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

/**
 * TODO  javadoc
 *
 * @author <a href='mailto:beckwithb@studentsonly.com'>Burt Beckwith</a>
 */
class GrailsNtlmProcessingFilterEntryPoint extends NtlmProcessingFilterEntryPoint {

	private final String STATE_ATTR = NtlmProcessingFilter.@STATE_ATTR
	private final Integer BEGIN = NtlmProcessingFilter.@BEGIN

	@Override
	void commence(ServletRequest req, ServletResponse res, AuthenticationException authException) throws IOException, ServletException {

		// start authentication, if necessary and forceIdentification in NtlmProcessingFilter is false
		if (!(authException instanceof NtlmBaseException
				|| authException instanceof BadCredentialsException)) {

	        request.session.setAttribute STATE_ATTR, BEGIN

			HttpServletResponse response = (HttpServletResponse)res

			response.setHeader 'WWW-Authenticate', new NtlmBeginHandshakeException().message
			response.setHeader 'Connection', 'Keep-Alive'
			response.status = HttpServletResponse.SC_UNAUTHORIZED
			response.contentLength = 0
			response.flushBuffer()
		}
		else {
			super.commence(req, res, authException)
		}
	}
}
