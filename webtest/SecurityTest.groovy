import grails.util.WebTest

class SecurityTest extends WebTest {

	private static final String ROW_COUNT_XPATH = "count(//div[@class='list']//tbody/tr)"

	/**
	 * The test suite.
	 */
	void suite() {
		testUserListNewDelete()
	}

	void testUserListNewDelete() {

		checkAnnotatedServiceInaccessibleWithoutRole()

		checkSecurePageVisibleWithoutRequestmap()

		createRole()
		createUser()

		createRequestMap()
		checkSecurePageNotVisibleWithRequestmap()

		loginAndCheckAllAllowed()
	}

	private void createRole() {
		webtest('Create the admin role') {
			invoke      (url: 'role')
			verifyText  (text:'Home')

			verifyListSize 0

			clickLink   (label:'New Role')
			verifyText  (text: 'Create Role')

			setInputField(name: 'authority', value: 'admin')
			setInputField(name: 'description', value: 'admin role')
			clickButton (label:'Create')

			verifyText  (text: 'Show Role', description:'Detail page')
			clickLink   (label:'List', description:'Back to list view')

			verifyListSize 1
		}
	}

	private void createUser() {
		webtest('Create the test user') {
			invoke      (url: 'user')
			verifyText  (text:'Home')

			verifyListSize 0

			clickLink   (label:'New User')
			verifyText  (text: 'Create User')

			setInputField(name: 'username', value: 'new_user')
			setInputField(name: 'userRealName', value: 'new user')
			setInputField(name: 'passwd', value: 'p4ssw0rd')
			setCheckbox(name: 'enabled')
			setInputField(name: 'description', value: 'a new user')
			setInputField(name: 'email', value: 'new@user.com')
			setCheckbox(name: 'emailShow')
			setCheckbox(name: 'ROLE_ADMIN')
			clickButton (label:'Create')

			verifyText  (text: 'Show User', description:'Detail page')
			clickLink   (label:'List', description:'Back to list view')

			verifyListSize 1
		}
	}

	private void checkAnnotatedServiceInaccessibleWithoutRole() {
		webtest('Check that without being logged in, annotationTest/admin is inaccessible') {
			invoke      (url: 'annotationTest')
			verifyText  (text:'anyone can see this')

			invoke      (url: 'annotationTest/admin')
			verifyText  (text:'Access is denied')
		}
	}

	private void checkSecurePageVisibleWithoutRequestmap() {
		webtest('Check that without a requestmap, /secure is accessible') {
			invoke      (url: 'secure')
			verifyText  (text:'SECURE')
		}
	}

	private void createRequestMap() {
		webtest('Create a Requestmap entry for /secure') {
			invoke      (url: 'requestmap')
			verifyText  (text:'Home')

			verifyListSize 0

			clickLink   (label:'New Requestmap')
			verifyText  (text: 'Create Requestmap')

			setInputField(name: 'url', value: '/secure/**')
			setInputField(name: 'configAttribute', value: 'admin')
			clickButton (label:'Create')

			verifyText  (text: 'Show Requestmap', description:'Detail page')
			clickLink   (label:'List', description:'Back to list view')

			verifyListSize 1
		}
	}

	private void checkSecurePageNotVisibleWithRequestmap() {
		webtest('Check that with a requestmap, /secure is not accessible') {
			invoke      (url: 'secure')
			verifyText  (text:'Please Login')
		}
	}

	private void loginAndCheckAllAllowed() {
		webtest('login and verify that secured pages are accessible') {
			// login
			invoke      (url: 'login/auth')
			verifyText  (text:'Please Login')

			setInputField(name: 'j_username', value: 'new_user')
			setInputField(name: 'j_password', value: 'p4ssw0rd')
			setCheckbox(name: '_spring_security_remember_me')
			clickButton (label:'Login')

			// Check that after login, annotationTest/admin is accessible
			invoke      (url: 'annotationTest/admin')
			verifyText  (text:'secure only')

			// Check that with a requestmap, /secure is accessible after login
			invoke      (url: 'secure')
			verifyText  (text:'SECURE')
		}
	}

	private void verifyListSize(final int size) {
		ant.group(description: "verify list view with $size row(s)") {
			verifyText  (text: 'List')
			verifyXPath (xpath: ROW_COUNT_XPATH, text: size, description: "$size row(s) of data expected")
		}
	}
}
