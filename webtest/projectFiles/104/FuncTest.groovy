import java.lang.reflect.Modifier

import org.apache.tools.ant.taskdefs.optional.junit.JUnitTest
import org.apache.tools.ant.taskdefs.optional.junit.PlainJUnitResultFormatter
import org.apache.tools.ant.taskdefs.optional.junit.XMLJUnitResultFormatter

import junit.framework.TestCase
import junit.framework.TestResult
import junit.framework.TestSuite

Ant.property(environment: 'env')
grailsHome = Ant.antProject.properties.'env.GRAILS_HOME'
result = new TestResult()

// Change default env to test
scriptEnv = 'test'

includeTargets << grailsScript('Init')
includeTargets << grailsScript('Bootstrap')
includeTargets << grailsScript('RunApp')
includeTargets << grailsScript('RunWar')

generateLog4jFile = true

reportsDir = 'test/reports'

target('default': 'Run functional tests') {
	depends(classpath, checkVersion, parseArguments, clean, cleanTestReports, configureProxy, packageApp, war)

	if (config.grails.testing.reports.destDir) {
		reportsDir = config.grails.testing.reports.destDir
	}

	Ant.mkdir(dir: reportsDir)
	Ant.mkdir(dir: "${reportsDir}/html")
	Ant.mkdir(dir: "${reportsDir}/plain")

	compileTests()
	packageTests()

	def server
	boolean completed = false
	String previousRunMode

	try {
		def savedOut = System.out
		def savedErr = System.err
		try {
			new File(reportsDir, 'bootstrap-out.txt').withOutputStream {outStream ->
				System.out = new PrintStream(outStream)
				new File(reportsDir, 'bootstrap-err.txt').withOutputStream {errStream ->
					System.err = new PrintStream(errStream)
					server = configureHttpServerForWar()
					server.start()
				}
			}
		}
		finally {
			System.out = savedOut
			System.err = savedErr
		}

		String testingBaseURL = "http://localhost:$serverPort$serverContextPath"
		if (!testingBaseURL.endsWith('/')) testingBaseURL += '/'
		System.setProperty('grails.functional.test.baseURL', testingBaseURL)
		previousRunMode = System.getProperty('grails.run.mode', '')
		System.setProperty('grails.run.mode', 'functional-test')

		System.out.println "Functional tests running with base url: ${testingBaseURL}"
		doFunctionalTests(args)
		produceReports()
		completed = true
	}
	catch (e) {
		e.printStackTrace()
		throw e
	}
	finally {
		if (server) {
			stopWarServer()
		}
		System.setProperty('grails.run.mode', previousRunMode)
		if (completed) {
			processResults()
		}
	}
}

private void runTests(suite, TestResult result, Closure callback) {
	for (TestSuite test in suite.tests()) {
		new File("${reportsDir}/FUNCTEST-${test.name}.xml").withOutputStream {xmlOut ->
			new File("${reportsDir}/plain/FUNCTEST-${test.name}.txt").withOutputStream {plainOut ->

				def savedOut = System.out
				def savedErr = System.err

				try {
					def outBytes = new ByteArrayOutputStream()
					def errBytes = new ByteArrayOutputStream()
					System.out = new PrintStream(outBytes)
					System.err = new PrintStream(errBytes)
					def xmlOutput = new XMLJUnitResultFormatter(output: xmlOut)
					def plainOutput = new PlainJUnitResultFormatter(output: plainOut)
					def junitTest = new JUnitTest(test.name)
					try {
						plainOutput.startTestSuite(junitTest)
						xmlOutput.startTestSuite(junitTest)
						savedOut.println "Running functional test ${test.name}..."
						long start = System.currentTimeMillis()
						int runCount = 0
						int failureCount = 0
						int errorCount = 0

						for (i in 0..<test.testCount()) {
							def thisTest = new TestResult()
							thisTest.addListener(xmlOutput)
							thisTest.addListener(plainOutput)
							def t = test.testAt(i)
							System.out.println "--Output from ${t.name}--"
							System.err.println "--Output from ${t.name}--"

							callback(test, {
								savedOut.print "    ${t.name}... "
								event('TestStart', [test, t, thisTest])
								// Let the test know where it can communicate with the user
								t.consoleOutput = savedOut
								test.runTest(t, thisTest)
								event('TestEnd', [test, t, thisTest])
								thisTest
							})
							runCount += thisTest.runCount()
							failureCount += thisTest.failureCount()
							errorCount += thisTest.errorCount()

							if (thisTest.errorCount() > 0 || thisTest.failureCount() > 0) {
								thisTest.errors().each {result.addError(t, it.thrownException())}
								thisTest.failures().each {result.addFailure(t, it.thrownException())}
							}
							else {
								savedOut.println ' Passed!'
							}
						}
						junitTest.setCounts(runCount, failureCount, errorCount)
						junitTest.setRunTime(System.currentTimeMillis() - start)
					}
					finally {
						String outString = outBytes.toString()
						String errString = errBytes.toString()
						new File("${reportsDir}/FUNCTEST-${test.name}-out.txt").write(outString)
						new File("${reportsDir}/FUNCTEST-${test.name}-err.txt").write(errString)
						plainOutput?.setSystemOutput(outString)
						plainOutput?.setSystemError(errString)
						plainOutput?.endTestSuite(junitTest)
						xmlOutput?.setSystemOutput(outString)
						xmlOutput?.setSystemError(errString)
						xmlOutput?.endTestSuite(junitTest)
					}
				}
				finally {
					System.out = savedOut
					System.err = savedErr
				}
			}
		}
	}
}

private void processResults() {
	if (result) {
		if (result.errorCount() || result.failureCount()) {
			event('StatusFinal', ["Tests failed: ${result.errorCount()} errors, ${result.failureCount()} failures. View reports in $reportsDir"])
			exit(1)
		}
		else {
			event('StatusFinal', ["Tests passed. View reports in $reportsDir"])
			exit(0)
		}
	}
	else {
		event('StatusFinal', ["Tests passed. View reports in $reportsDir"])
		exit(0)
	}
}

private void packageTests() {
	Ant.copy(todir: testDirPath) {
		fileset(dir: basedir, includes: 'application.properties')
	}
	Ant.copy(todir: testDirPath, failonerror: false) {
		fileset(dir: "${basedir}/grails-app/conf", includes: '**', excludes: '*.groovy, log4j*, hibernate, spring')
		fileset(dir: "${basedir}/grails-app/conf/hibernate", includes: '**/**')
		fileset(dir: "${basedir}/src/java") {
			include(name: '**/**')
			exclude(name: '**/*.java')
		}
		fileset(dir: "${basedir}/test/functional") {
			include(name: '**/**')
			exclude(name: '**/*.java')
			exclude(name: '**/*.groovy)')
		}
	}
}

private void compileTests() {
	event('CompileStart', ['functional-tests'])

	String destDir = testDirPath
	Ant.mkdir(dir: destDir)
	try {
		def nonTestCompilerClasspath = compilerClasspath.curry(false)
		Ant.groovyc(destdir: destDir,
			projectName: grailsAppName,
			encoding: 'UTF-8',
			classpathref: 'grails.classpath', {
				nonTestCompilerClasspath.delegate = delegate
				nonTestCompilerClasspath.call()
				src(path: "${basedir}/test/functional")
			})
	}
	catch (e) {
		event('StatusFinal', ["Compilation Error: ${e.message}"])
		exit(1)
	}

	classLoader = new URLClassLoader([new File(destDir).toURI().toURL()] as URL[], classLoader)
	Thread.currentThread().contextClassLoader = classLoader

	event('CompileEnd', ['functional-tests'])
}

private void produceReports() {
	Ant.junitreport(todir: reportsDir) {
		fileset(dir: reportsDir) { include(name: 'FUNCTEST-*.xml') }
		report(format: 'frames', todir: "${reportsDir}/html")
	}
}

private void doFunctionalTests(args) {
	try {
		def suite = createTestSuite(args)
		if (suite.testCount() == 0) {
			return
		}

		event('TestSuiteStart', ['functional'])
		int testCases = suite.countTestCases()
		println '-------------------------------------------------------'
		println "Running ${testCases} Functional Test${testCases > 1 ? 's' : ''}..."

		def start = new Date()
		runTests(suite, result) {test, invocation ->
			invocation()
		}
		def end = new Date()

		event('TestSuiteEnd', ['functional', suite])
		event('StatusUpdate', ["Functional Tests Completed in ${end.time - start.time}ms"])
		println '-------------------------------------------------------'
	}
	catch (e) {
		event('StatusFinal', ["Error running functional tests: ${e.toString()}"])
		e.printStackTrace()
	}
}

private TestSuite createTestSuite(args) {

	TestSuite testSuite = new TestSuite('Grails Test Suite')

	ClassLoader currentClassLoader = new URLClassLoader(
		[new File('test/functional').toURI().toURL(),
		 new File(testDirPath).toURI().toURL()] as URL[],
		classLoader)

	def testNames = args.split('\n') as List
	if (testNames) {
		classLoader.rootLoader.addURL(new File('test/functional').toURI().toURL())
		for (String testName in testNames) {
			def suite = currentClassLoader.loadClass(testName).suite()
			suite.testCount().times { i -> testSuite.addTest(suite.testAt(i)) }
		}
	}

	return testSuite
}

