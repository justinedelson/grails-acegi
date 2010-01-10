import grails.util.WebTest

/**
 * Suite for tests that use the static configuration.
 */
class StaticSuite extends WebTest {

	static void main(args) {
		new StaticSuite().runTests()
	}

	/**
	 * Runs the tests in order since the security tests don't cleanup afterwards.
	 */
	void suite() {
		new RoleTest(ant: ant, configMap: configMap).suite()
		new UserTest(ant: ant, configMap: configMap).suite()
		new StaticSecurityTest(ant: ant, configMap: configMap).suite()
	}
}
