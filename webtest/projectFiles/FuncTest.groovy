import junit.framework.TestSuite

import org.codehaus.groovy.grails.test.DefaultGrailsTestRunner
import org.codehaus.groovy.grails.test.GrailsTestHelper

includeTargets << grailsScript('_GrailsClean')
includeTargets << grailsScript('_GrailsTest')

target('default': 'Run functional tests') {
	depends(checkVersion, configureProxy, parseArguments, cleanTestReports, clean)

	ant.mkdir(dir: testReportsDir)
	ant.mkdir(dir: "${testReportsDir}/html")
	ant.mkdir(dir: "${testReportsDir}/plain")

	testRunner = new DefaultGrailsTestRunner(testReportsDir, reportFormats)

	packageApp()
	runApp()
	testHelper = new TestHelper(grailsSettings, classLoader)
	testNames = args.split('\n') as List

	processTests 'functional'

	stopServer()

	produceReports()
	String msg = (testsFailed ? "\nTests FAILED" : "\nTests PASSED") + " - view reports in ${testReportsDir}."
	event('StatusFinal', [msg])
	return testsFailed ? 1 : 0
}

class TestHelper implements GrailsTestHelper {

	private final File testClassesDir
	private final ClassLoader parentLoader
	private final File baseDir

	ClassLoader currentClassLoader

	TestHelper(settings, ClassLoader classLoader) {
		testClassesDir = settings.testClassesDir
		baseDir = settings.baseDir
		parentLoader = classLoader
	}

	TestSuite createTests(List<String> testNames, String type) {
		String testSrcDir = "${baseDir.absolutePath}/test/$type"
		TestSuite testSuite = new TestSuite('Grails Test Suite')

		currentClassLoader = new URLClassLoader([
				new File('test/functional').toURI().toURL(),
				new File(testClassesDir, type).toURI().toURL()] as URL[],
				parentLoader)

		for (String testName in testNames) {
			def suite = currentClassLoader.loadClass(testName).suite()
			suite.testCount().times { i -> testSuite.addTest(suite.testAt(i)) }
		}

		testSuite
	}
}
