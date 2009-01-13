import grails.util.WebTest

class RoleTest extends WebTest {

	private static final String ROW_COUNT_XPATH = "count(//div[@class='list']//tbody/tr)"

	/**
	 * The test suite.
	 */
	void suite() {
		testRoleListNewDelete()
	}

	void testRoleListNewDelete() {
		webtest('Role basic operations: view list, create new entry, view, edit, delete, view') {
			invoke      (url: 'testRole')
			verifyText  (text:'Home')

			verifyListSize 0

			clickLink   (label:'New TestRole')
			verifyText  (text: 'Create TestRole')

			setInputField(name: 'authority', value: 'test')
			setInputField(name: 'description', value: 'test role')
			clickButton (label:'Create')

			verifyText  (text: 'Show TestRole', description:'Detail page')
			clickLink   (label:'List', description:'Back to list view')

			verifyListSize 1

			group(description:'edit the one element') {
				showFirstElementDetails()
				clickButton (label:'Edit')
				verifyText  (text: 'Edit TestRole')

				setInputField(name: 'authority', value: 'test_new')
				setInputField(name: 'description', value: 'test role 2')
				clickButton (label:'Update')

				verifyText  (text: 'Show TestRole')
				clickLink   (label:'List', description:'Back to list view')
			}

			verifyListSize 1

			group(description:'delete the only element') {
				showFirstElementDetails()
				clickButton (label:'Delete')
				verifyXPath (xpath:"//div[@class='message']", text: /.*TestRole.*deleted.*/, regex: true)
			}

			verifyListSize 0
		}
	}

	private void verifyListSize(int size) {
		ant.group(description:"verify TestRole list view with $size row(s)") {
			verifyText  (text:'TestRole List')
			verifyXPath (xpath:ROW_COUNT_XPATH, text:size, description:"$size row(s) of data expected")
		}
	}

	private void showFirstElementDetails() {
		ant.clickLink(href: '/testRole/show/1', description: 'go to detail view')
	}
}
