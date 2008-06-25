import grails.util.WebTest

class RequestmapTest extends WebTest {

	private static final String ROW_COUNT_XPATH = "count(//div[@class='list']//tbody/tr)"

	/**
	 * The test suite.
	 */
	void suite() {
		testRequestmapListNewDelete()
	}

	void testRequestmapListNewDelete() {
		webtest('Requestmap basic operations: view list, create new entry, view, edit, delete, view') {
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

			group(description:'edit the one element') {
				showFirstElementDetails()
				clickButton (label:'Edit')
				verifyText  (text: 'Edit Requestmap')
				clickButton (label:'Update')
				verifyText  (text: 'Show Requestmap')
				clickLink   (label:'List', description:'Back to list view')
			}

			verifyListSize 1

			group(description:'delete the only element') {
				showFirstElementDetails()
				clickButton (label:'Delete')
				verifyXPath (xpath:"//div[@class='message']", text:/.*Requestmap.*deleted.*/, regex:true)
			}

			verifyListSize 0
		}
	}

	private void verifyListSize(int size) {
		ant.group(description:"verify Requestmap list view with $size row(s)") {
			verifyText  (text:'Requestmap List')
			verifyXPath (xpath:ROW_COUNT_XPATH, text:size, description:"$size row(s) of data expected")
		}
	}

	private void showFirstElementDetails() {
		ant.clickLink(href: '/requestmap/show/1', description:'go to detail view')
	}
}
