class RequestmapTest extends AbstractSecurityWebTest {

	/**
	 * The test suite.
	 */
	void suite() {
		testRequestmapListNewDelete()
	}

	void testRequestmapListNewDelete() {
		webtest('Requestmap basic operations: view list, create new entry, view, edit, delete, view') {
			invoke      (url: 'testRequestmap')
			verifyText  (text:'Home')

			verifyListSize 0

			clickLink   (label:'New TestRequestmap')
			verifyText  (text: 'Create TestRequestmap')

			setInputField(name: 'url', value: '/secure/**')
			setInputField(name: 'configAttribute', value: 'ROLE_ADMIN')
			clickButton (label:'Create')

			verifyText  (text: 'Show TestRequestmap', description:'Detail page')
			clickLink   (label:'List', description:'Back to list view')

			verifyListSize 1

			group(description:'edit the one element') {
				showFirstElementDetails()
				clickButton (label:'Edit')
				verifyText  (text: 'Edit TestRequestmap')
				clickButton (label:'Update')
				verifyText  (text: 'Show TestRequestmap')
				clickLink   (label:'List', description:'Back to list view')
			}

			verifyListSize 1

			group(description:'delete the only element') {
				showFirstElementDetails()
				clickButton (label:'Delete')
				verifyXPath (xpath:"//div[@class='message']", text:/.*TestRequestmap.*deleted.*/, regex:true)
			}

			verifyListSize 0
		}
	}

	private void showFirstElementDetails() {
		ant.clickLink(href: '/testRequestmap/show/1', description:'go to detail view')
	}
}
