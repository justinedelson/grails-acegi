class AnnotationSecurityTest extends AbstractSecurityWebTest {

	/**
	 * The test suite.
	 */
	void suite() {
		testUserListNewDelete()
	}

	void testUserListNewDelete() {

		createRoles()
		createUsers()

		checkSecuredUrlsNotVisibleWithoutLogin()

		loginAndCheckAllAllowed()
	}

	private void createRoles() {
		webtest('Create the admin roles') {
			invoke      (url: 'testRole')
			verifyText  (text:'Home')

			verifyListSize 0

			clickLink   (label:'New TestRole')
			verifyText  (text: 'Create TestRole')

			setInputField(name: 'authority', value: 'ROLE_ADMIN')
			setInputField(name: 'description', value: 'admin role')
			clickButton (label:'Create')

			verifyText  (text: 'Show TestRole', description:'Detail page')
			clickLink   (label:'List', description:'Back to list view')

			verifyListSize 1

			clickLink   (label:'New TestRole')
			verifyText  (text: 'Create TestRole')

			setInputField(name: 'authority', value: 'ROLE_ADMIN2')
			setInputField(name: 'description', value: 'admin role 2')
			clickButton (label:'Create')

			verifyText  (text: 'Show TestRole', description:'Detail page')
			clickLink   (label:'List', description:'Back to list view')

			verifyListSize 2
		}
	}

	private void createUsers() {
		webtest('Create the test user') {
			invoke      (url: 'testUser')
			verifyText  (text:'Home')

			verifyListSize 0

			clickLink   (label:'New TestUser')
			verifyText  (text: 'Create TestUser')

			setInputField(name: 'username', value: 'admin1')
			setInputField(name: 'userRealName', value: 'admin 1')
			setInputField(name: 'passwd', value: 'password1')
			setCheckbox(name: 'enabled')
			setInputField(name: 'description', value: 'admin 1')
			setInputField(name: 'email', value: 'admin1@foo.com')
			setCheckbox(name: 'emailShow')
			setCheckbox(name: 'ROLE_ADMIN')
			clickButton (label:'Create')

			verifyText  (text: 'Show TestUser', description:'Detail page')
			clickLink   (label:'List', description:'Back to list view')

			verifyListSize 1

			clickLink   (label:'New TestUser')
			verifyText  (text: 'Create TestUser')

			setInputField(name: 'username', value: 'admin2')
			setInputField(name: 'userRealName', value: 'admin 2')
			setInputField(name: 'passwd', value: 'password2')
			setCheckbox(name: 'enabled')
			setInputField(name: 'description', value: 'admin 2')
			setInputField(name: 'email', value: 'admin2@foo.com')
			setCheckbox(name: 'emailShow')
			setCheckbox(name: 'ROLE_ADMIN')
			setCheckbox(name: 'ROLE_ADMIN2')
			clickButton (label:'Create')

			verifyText  (text: 'Show TestUser', description:'Detail page')
			clickLink   (label:'List', description:'Back to list view')

			verifyListSize 2
		}
	}

	private void checkSecuredUrlsNotVisibleWithoutLogin() {
		webtest('Check that without being logged in, @Secure actions are not accessible') {

			invoke      (url: 'logout')
			verifyText  (text:'Welcome to Grails')

			invoke      (url: 'secureAnnotated')
			verifyText  (text:'Please Login')

			invoke      (url: 'secureAnnotated/index')
			verifyText  (text:'Please Login')

			invoke      (url: 'secureAnnotated/adminEither')
			verifyText  (text:'Please Login')

			invoke      (url: 'secureClassAnnotated')
			verifyText  (text:'Please Login')

			invoke      (url: 'secureClassAnnotated/index')
			verifyText  (text:'Please Login')

			invoke      (url: 'secureClassAnnotated/otherAction')
			verifyText  (text:'Please Login')

			invoke      (url: 'secureClassAnnotated/admin2')
			verifyText  (text:'Please Login')
		}
	}

	private void loginAndCheckAllAllowed() {
		webtest('login and verify that secured pages are accessible') {
			// login as admin1
			invoke      (url: 'login/auth')
			verifyText  (text:'Please Login')

			setInputField(name: 'j_username', value: 'admin1')
			setInputField(name: 'j_password', value: 'password1')
			setCheckbox(name: '_spring_security_remember_me')
			clickButton (label: 'Login')

			// Check that after login as admin1, some @Secure actions are accessible
			invoke      (url: 'secureAnnotated')
			verifyText  (text:'you have ROLE_ADMIN')

			invoke      (url: 'secureAnnotated/index')
			verifyText  (text:'you have ROLE_ADMIN')

			invoke      (url: 'secureAnnotated/adminEither')
			verifyText  (text:'you have ROLE_ADMIN')

			invoke      (url: 'secureClassAnnotated')
			verifyText  (text:'you have ROLE_ADMIN')

			invoke      (url: 'secureClassAnnotated/index')
			verifyText  (text:'you have ROLE_ADMIN')

			invoke      (url: 'secureClassAnnotated/otherAction')
			verifyText  (text:'you have ROLE_ADMIN')

			invoke      (url: 'secureClassAnnotated/admin2')
			verifyText  (text:"Sorry, you're not authorized to view this page.")

			// login as admin2
			invoke      (url: 'logout')
			verifyText  (text:'Welcome to Grails')

			invoke      (url: 'login/auth')
			verifyText  (text:'Please Login')

			setInputField(name: 'j_username', value: 'admin2')
			setInputField(name: 'j_password', value: 'password2')
			setCheckbox(name: '_spring_security_remember_me')
			clickButton (label: 'Login')

			// Check that after login as admin2, some @Secure actions are accessible
			invoke      (url: 'secureAnnotated')
			verifyText  (text:'you have ROLE_ADMIN')

			invoke      (url: 'secureAnnotated/index')
			verifyText  (text:'you have ROLE_ADMIN')

			invoke      (url: 'secureAnnotated/adminEither')
			verifyText  (text:'you have ROLE_ADMIN')

			invoke      (url: 'secureClassAnnotated')
			verifyText  (text:'index: you have ROLE_ADMIN')

			invoke      (url: 'secureClassAnnotated/index')
			verifyText  (text:'index: you have ROLE_ADMIN')

			invoke      (url: 'secureClassAnnotated/otherAction')
			verifyText  (text:'otherAction: you have ROLE_ADMIN')

			invoke      (url: 'secureClassAnnotated/admin2')
			verifyText  (text:'admin2: you have ROLE_ADMIN2')
		}
	}
}

