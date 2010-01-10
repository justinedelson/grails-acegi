import grails.util.WebTest

abstract class AbstractSecurityWebTest extends WebTest {

	protected static final String ROW_COUNT_XPATH = "count(//div[@class='list']//tbody/tr)"

	protected void verifyListSize(int size) {
		ant.group(description: "verify list view with $size row(s)") {
			verifyText  (text: 'List')
			verifyXPath (xpath: ROW_COUNT_XPATH, text: size, description: "$size row(s) of data expected")
		}
	}
}
