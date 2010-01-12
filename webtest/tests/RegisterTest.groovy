class RegisterTest extends AbstractSecurityWebTest {

	void testCreateRole() {
		get '/testRole'
		assertContentContains 'Home'

		verifyListSize 0

		click 'New TestRole'
		assertContentContains 'Create TestRole'

		form {
			authority = 'ROLE_ADMIN'
			description = 'ROLE_ADMIN'
		}
		clickButton 'Create'

		assertContentContains 'Show TestRole'
		click 'TestRole List'

		verifyListSize 1
	}

	void testRegisterMismatchPassword() {
		get '/register'
		assertContentContains 'User Registration'

		// need to simulate pulling the dynamic image
		getInNewPage '/captcha', sessionId

		String captchaValue = getSessionValue('captcha', sessionId)
		form {
			username = 'new_user'
			userRealName = 'new user'
			passwd = 'p4ssw0rd'
			repasswd = 'password'
			email = "register${System.currentTimeMillis()}@burtbeckwith.com"
			captcha = captchaValue
			clickButton 'Create'
		}

		assertContentContains 'The passwords you entered do not match.'
	}

	void testRegisterWrongCaptcha() {
		get '/register'
		assertContentContains 'User Registration'

		form {
			username = 'new_user'
			userRealName = 'new user'
			passwd = 'p4ssw0rd'
			repasswd = 'p4ssw0rd'
			email = "register${System.currentTimeMillis()}@burtbeckwith.com"
			captcha = 'asd123'

			clickButton 'Create'
		}

		assertContentContains 'Access code did not match.'
	}

	void testRegisterOk() {
		get '/register'
		assertContentContains 'User Registration'

		// need to simulate pulling the dynamic image
		getInNewPage '/captcha', sessionId

		String captchaValue = getSessionValue('captcha', sessionId)
		form {
			username = 'new_user'
			userRealName = 'new user'
			passwd = 'p4ssw0rd'
			repasswd = 'p4ssw0rd'
			email = "register${System.currentTimeMillis()}@burtbeckwith.com"
			captcha = captchaValue

			clickButton 'Create'
		}

		assertContentContains 'Welcome to Grails'

		// check session auth
		String auth = getSessionValue('SPRING_SECURITY_CONTEXT', sessionId)
		assertTrue auth.contains('ROLE_ADMIN')
		assertTrue auth.contains('Authenticated:true')

		// check that we're logged in
		get '/secureAnnotated/index'
		assertContentContains 'you have ROLE_ADMIN'
	}
}
