import grails.util.WebTest

/**
 * Suite for all webtests in the application.
 */
class TestSuite extends WebTest {

	static void main(args) {
		new TestSuite().runTests()
	}

	/**
	 * Runs the tests in order since the security tests don't cleanup afterwards.
	 */
	void suite() {
		new RequestmapTest(ant: ant, configMap: configMap).suite()
		new RoleTest(ant: ant, configMap: configMap).suite()
		new UserTest(ant: ant, configMap: configMap).suite()
		new SecurityTest(ant: ant, configMap: configMap).suite()
	}
}
