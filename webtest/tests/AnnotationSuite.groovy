import grails.util.WebTest

/**
 * Suite for tests that use the Controller annotation configuration.
 */
class AnnotationSuite extends WebTest {

	static void main(args) {
		new AnnotationSuite().runTests()
	}

	/**
	 * Runs the tests in order since the security tests don't cleanup afterwards.
	 */
	void suite() {
		new RoleTest(ant: ant, configMap: configMap).suite()
		new UserTest(ant: ant, configMap: configMap).suite()
		new AnnotationSecurityTest(ant: ant, configMap: configMap).suite()
	}
}
