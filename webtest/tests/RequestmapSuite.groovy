import grails.util.WebTest

/**
 * Suite for tests that use the Requestmap configuration.
 */
class RequestmapSuite extends WebTest {

	static void main(args) {
		new RequestmapSuite().runTests()
	}

	/**
	 * Runs the tests in order since the security tests don't cleanup afterwards.
	 */
	void suite() {
		new RequestmapTest(ant: ant, configMap: configMap).suite()
		new RoleTest(ant: ant, configMap: configMap).suite()
		new UserTest(ant: ant, configMap: configMap).suite()
		new RequestmapSecurityTest(ant: ant, configMap: configMap).suite()
//		new RegisterTest(ant: ant, configMap: configMap).suite()
	}
}
