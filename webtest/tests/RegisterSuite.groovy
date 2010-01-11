import junit.framework.TestSuite

/**
 * Suite for registration tests.
 */
class RegisterSuite extends functionaltestplugin.FunctionalTestCase {

	/**
	 * Runs the tests in order since the security tests don't cleanup afterwards.
	 */
	static TestSuite suite() {
		new TestSuite([RegisterTest] as Class[])
	}
}
