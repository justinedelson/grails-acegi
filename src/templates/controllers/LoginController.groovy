import org.codehaus.groovy.grails.plugins.springsecurity.service.AuthenticateService
import org.springframework.security.DisabledException
import org.springframework.security.ui.AbstractProcessingFilter
import org.springframework.security.ui.webapp.AuthenticationProcessingFilter

/**
 * Login Controller (Example).
 */
class LoginController {

	AuthenticateService authenticateService

	def index = {
		if (isLoggedIn()) {
			redirect(uri: '/')
		}
		else {
			redirect(action: auth, params: params)
		}
	}

	/**
	 * Show the login page.
	 */
	def auth = {
		nocache(response)
		if (isLoggedIn()) {
			redirect(uri: '/')
		}
	}

	// Login page (function|json) for Ajax access.
	def authAjax = {
		nocache(response)
		//this is example:
		render """
		<script type='text/javascript'>
		(function() {
			loginForm();
		})();
		</script>
		"""
	}

	/**
	 * The Ajax success redirect url.
	 */
	def ajaxSuccess = {
		nocache(response)
		render '{success: true}'
	}

	/**
	 * Show denied page.
	 */
	def denied = {
		redirect(uri: '/')
	}

	// Denial page (data|view|json) for Ajax access.
	def deniedAjax = {
		//this is example:
		render "{error: 'access denied'}"
	}

	/**
	 * login failed
	 */
	def authfail = {

		def username = session[AuthenticationProcessingFilter.SPRING_SECURITY_LAST_USERNAME_KEY]
		def msg = ''
		def exception = session[AbstractProcessingFilter.SPRING_SECURITY_LAST_EXCEPTION_KEY]
		if (exception) {
			if (exception instanceof DisabledException) {
				msg = "[$username] is disabled."
			}
			else {
				msg = "[$username] wrong username/password."
			}
		}

		//is ajax access?
		def ajaxHeader = authenticateService.securityConfig.security.ajaxHeader
		boolean isAjax = request.getHeader(ajaxHeader) != null
		if (!isAjax) {
			def savedRequest = session[AbstractProcessingFilter.SPRING_SECURITY_SAVED_REQUEST_KEY]
			if (savedRequest) {
				isAjax = savedRequest.getHeader(ajaxHeader) != null
			}
		}

		if (isAjax) {
			render("{error: '${msg}'}")
		}
		else {
			flash.message = msg
			redirect(action: auth, params: params)
		}
	}

	/**
	 * Check if logged in.
	 */
	private boolean isLoggedIn() {
		def authPrincipal = authenticateService.principal()
		return authPrincipal != null && authPrincipal != 'anonymousUser'
	}

	/** cache controls */
	private void nocache(response) {
		response.setHeader('Cache-Control', 'no-cache') // HTTP 1.1
		response.addDateHeader('Expires', 0)
		response.setDateHeader('max-age', 0) 
		response.setIntHeader ('Expires', -1) //prevents caching at the proxy server 
		response.addHeader('cache-Control', 'private') //IE5.x only
	}
}
