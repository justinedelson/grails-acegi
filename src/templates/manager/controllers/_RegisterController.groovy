${personClassImport}
${authorityClassImport}

import org.springframework.security.providers.UsernamePasswordAuthenticationToken as AuthToken
import org.springframework.security.context.SecurityContextHolder as SCH

/**
 * Registration controller.
 */
class RegisterController {

	def authenticateService
	def daoAuthenticationProvider
	def emailerService

	static Map allowedMethods = [save: 'POST', update: 'POST']

	/**
	 * User Registration Top page.
	 */
	def index = {

		// skip if already logged in
		if (authenticateService.isLoggedIn()) {
			redirect action: show
			return
		}

		if (session.id) {
			def person = new ${personClassName}()
			person.properties = params
			return [person: person]
		}

		redirect uri: '/'
	}

	/**
	 * User Information page for current user.
	 */
	def show = {

		// get user id from session's domain class.
		def user = authenticateService.userDomain()
		if (user) {
			render view: 'show', model: [person: ${personClassName}.get(user.id)]
		}
		else {
			redirect action: index
		}
	}

	/**
	 * Edit page for current user.
	 */
	def edit = {

		def person
		def user = authenticateService.userDomain()
		if (user) {
			person = ${personClassName}.get(user.id)
		}

		if (!person) {
			flash.message = "[Illegal Access] User not found with id \${params.id}"
			redirect action: index
			return
		}

		[person: person]
	}

	/**
	 * update action for current user's edit page
	 */
	def update = {

		def person
		def user = authenticateService.userDomain()
		if (user) {
			person = ${personClassName}.get(user.id)
		}
		else {
			redirect action: index
			return
		}

		if (!person) {
			flash.message = "[Illegal Access] User not found with id \${params.id}"
			redirect action: index, id: params.id
			return
		}

		// if user want to change password. leave passwd field blank, passwd will not change.
		if (params.passwd && params.passwd.length() > 0
				&& params.repasswd && params.repasswd.length() > 0) {
			if (params.passwd == params.repasswd) {
				person.${passwordField} = authenticateService.encodePassword(params.passwd)
			}
			else {
				person.${passwordField} = ''
				flash.message = 'The passwords you entered do not match.'
				render view: 'edit', model: [person: person]
				return
			}
		}

		person.userRealName = params.userRealName
		person.email = params.email
		if (params.emailShow) {
			person.emailShow = true
		}
		else {
			person.emailShow = false
		}

		if (person.save()) {
			redirect action: show, id: person.id
		}
		else {
			render view: 'edit', model: [person: person]
		}
	 }

	/**
	 * Person save action.
	 */
	def save = {

		// skip if already logged in
		if (authenticateService.isLoggedIn()) {
			redirect action: show
			return
		}

		def person = new ${personClassName}()
		person.properties = params

		def config = authenticateService.securityConfig
		def defaultRole = config.security.defaultRole

		def role = ${authorityClassName}.findByAuthority(defaultRole)
		if (!role) {
			person.${passwordField} = ''
			flash.message = "Default Role '\$defaultRole' not found."
			render view: 'index', model: [person: person]
			return
		}

		if (params.captcha.toUpperCase() != session.captcha) {
			person.${passwordField} = ''
			flash.message = 'Access code did not match.'
			render view: 'index', model: [person: person]
			return
		}

		if (params.passwd != params.repasswd) {
			person.${passwordField} = ''
			flash.message = 'The passwords you entered do not match.'
			render view: 'index', model: [person: person]
			return
		}

		def pass = authenticateService.encodePassword(params.passwd)
		bindData(person, [
				${usernameField}: params.username,
				${passwordField}: pass,
				enabled: true,
				emailShow: true,
				description: '' ])
		if (person.save()) {
			role.addToPeople(person)
			if (config.security.useMail) {
				String emailContent = """You have signed up for an account at:

 \${request.scheme}://\${request.serverName}:\${request.serverPort}\${request.contextPath}

 Here are the details of your account:
 -------------------------------------
 LoginName: \${person.${usernameField}}
 Email: \${person.email}
 Full Name: \${person.userRealName}
"""

				def email = [
					to: [person.email], // 'to' expects a List, NOT a single email address
					subject: "[\${request.contextPath}] Account Signed Up",
					text: emailContent // 'text' is the email body
				]
				emailerService.sendEmails([email])
			}

			person.save(flush: true)

			def auth = new AuthToken(person.${usernameField}, params.passwd)
			def authtoken = daoAuthenticationProvider.authenticate(auth)
			SCH.context.authentication = authtoken
			redirect uri: '/'
		}
		else {
			person.${passwordField} = ''
			render view: 'index', model: [person: person]
		}
	}
}
