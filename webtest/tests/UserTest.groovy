class UserTest extends AbstractSecurityWebTest {

	/**
	 * The test suite.
	 */
	void suite() {
		testUserListNewDelete()
	}

	void testUserListNewDelete() {
		webtest('User basic operations: view list, create new entry, view, edit, delete, view') {
			invoke      (url: 'testUser')
			verifyText  (text:'Home')

			verifyListSize 0

			clickLink   (label:'New TestUser')
			verifyText  (text: 'Create TestUser')

			setInputField(name: 'username', value: 'new_user')
			setInputField(name: 'userRealName', value: 'new user')
			setInputField(name: 'passwd', value: 'p4ssw0rd')
			setCheckbox(name: 'enabled')
			setInputField(name: 'description', value: 'a new user')
			setInputField(name: 'email', value: 'new@user.com')
			setCheckbox(name: 'emailShow')
			clickButton (label:'Create')

			verifyText  (text: 'Show TestUser', description:'Detail page')
			clickLink   (label:'List', description:'Back to list view')

			verifyListSize 1

			group(description:'edit the one element') {
				showFirstElementDetails()
				clickButton (label:'Edit')
				verifyText  (text: 'Edit TestUser')

				setInputField(name: 'username', value: 'new_user2')
				setInputField(name: 'userRealName', value: 'new user2')
				setInputField(name: 'passwd', value: 'p4ssw0rd2')
				setCheckbox(name: 'enabled', checked: false)
				setInputField(name: 'description', value: 'a new user 2')
				setInputField(name: 'email', value: 'new@user2.com')
				setCheckbox(name: 'emailShow', checked: false)
				clickButton (label:'Update')

				verifyText  (text: 'Show TestUser')
				clickLink   (label:'List', description:'Back to list view')
			}

			verifyListSize 1

			group(description:'delete the only element') {
				showFirstElementDetails()
				clickButton (label:'Delete')
				verifyXPath (xpath:"//div[@class='message']", text:/.*TestUser.*deleted.*/, regex:true)
			}

			verifyListSize 0
		}
	}

	private void showFirstElementDetails() {
		ant.clickLink(href: '/testUser/show/1', description: 'go to detail view')
	}
}
