import org.springframework.security.providers.encoding.MessageDigestPasswordEncoder

class MiscTest extends AbstractSecurityWebTest {

	void testSaltedPassword() {
		createRoles()
		createUsers()

		String sql = "select passwd from test_user where username='user1'"
		def response = getInNewPage('/hack/executeQuery?sql=' + URLEncoder.encode(sql))
		String encryptedPassword = stripWS(response.contentAsString)

		def passwordEncoder = new MessageDigestPasswordEncoder('SHA')
		String notSalted = passwordEncoder.encodePassword('p4ssw0rd', null)
		String salted = passwordEncoder.encodePassword('p4ssw0rd', 'user1')

		assertEquals salted, encryptedPassword
		assertFalse notSalted == encryptedPassword
	}

	private void createRoles() {

		// admin
		get '/testRole'
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

		// user
		get '/testRole'
		click 'New TestRole'
		assertContentContains 'Create TestRole'

		form {
			authority = 'ROLE_USER'
			description = 'ROLE_USER'
		}
		clickButton 'Create'

		assertContentContains 'Show TestRole'
		click 'TestRole List'
		verifyListSize 2
	}

	private void createUsers() {

		// user1
		get '/testUser'
		verifyListSize 0

		click 'New TestUser'
		assertContentContains 'Create TestUser'

		form {
			username = 'user1'
			userRealName = 'user1'
			passwd = 'p4ssw0rd'
			enabled = true
			description = 'user1'
			email = 'user1@user.com'
			emailShow = true
			ROLE_ADMIN = true
		}
		clickButton 'Create'

		assertContentContains 'Show TestUser'
		click 'TestUser List'
		verifyListSize 1

		// user2
		get '/testUser'
		click 'New TestUser'
		assertContentContains 'Create TestUser'

		form {
			username = 'user2'
			userRealName = 'user2'
			passwd = 'p4ssw0rd2'
			enabled = true
			description = 'user2'
			email = 'user2@user.com'
			emailShow = true
			ROLE_USER = true
		}
		clickButton 'Create'

		assertContentContains 'Show TestUser'
		click 'TestUser List'
		verifyListSize 2
	}

	void testSwitchUser() {

		// login as user1
		get '/login/auth'
		assertContentContains 'Please Login'

		form {
			j_username = 'user1'
			j_password = 'p4ssw0rd'
			_spring_security_remember_me = true
			clickButton 'Login'
		}

		// verify logged in
		get '/secureAnnotated'
		assertContentContains 'you have ROLE_ADMIN'

		String auth = getSessionValue('SPRING_SECURITY_CONTEXT', sessionId)
		assertTrue auth.contains('Username:user1')
		assertTrue auth.contains('Authenticated:true')
		assertTrue auth.contains('ROLE_ADMIN')
		assertFalse auth.contains('ROLE_USER')
		assertFalse auth.contains('ROLE_PREVIOUS_ADMINISTRATOR')

		// switch
		get '/j_spring_security_switch_user?j_username=user2'
		assertContentContains 'Welcome to Grails'

		// verify logged in as user1

		auth = getSessionValue('SPRING_SECURITY_CONTEXT', sessionId)
		assertTrue auth.contains('Username:user2')
		assertTrue auth.contains('Authenticated:true')
		assertTrue auth.contains('ROLE_USER')
		assertTrue auth.contains('ROLE_PREVIOUS_ADMINISTRATOR')

		get '/secureAnnotated/userAction'
		assertContentContains 'you have ROLE_USER'

		// verify not logged in as admin
		get '/secureAnnotated/adminEither'
		assertContentContains "Sorry, you're not authorized to view this page."

		// switch back
		get '/j_spring_security_exit_user'
		assertContentContains 'Welcome to Grails'

		// verify logged in as admin
		get '/secureAnnotated/adminEither'
		assertContentContains 'you have ROLE_ADMIN'

		auth = getSessionValue('SPRING_SECURITY_CONTEXT', sessionId)
		assertTrue auth.contains('Username:user1')
		assertTrue auth.contains('Authenticated:true')
		assertTrue auth.contains('ROLE_ADMIN')
		assertFalse auth.contains('ROLE_USER')
		assertFalse auth.contains('ROLE_PREVIOUS_ADMINISTRATOR')
	}
	
	void testHierarchicalRoles() {

		// login as user1
		get '/login/auth'
		assertContentContains 'Please Login'

		form {
			j_username = 'user1'
			j_password = 'p4ssw0rd'
			_spring_security_remember_me = true
			clickButton 'Login'
		}

		// verify logged in
		get '/secureAnnotated'
		assertContentContains 'you have ROLE_ADMIN'
		
		String auth = getSessionValue('SPRING_SECURITY_CONTEXT', sessionId)
		assertTrue auth.contains('Authenticated:true')
		assertFalse auth.contains('ROLE_USER')

		// now get an action that's ROLE_USER only
		get '/secureAnnotated/userAction'
		assertContentContains 'you have ROLE_USER'
	}
}
