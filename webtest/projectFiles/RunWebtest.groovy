/*
 * Copyright 2004-2005 the original author or authors.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * Gant script that runs all the webtests against a Grails application
 * 
 * @author Graeme Rocher
 * @author Dierk Koenig
 * @author Bernd Schiffer
 *
 * @since 0.4
 */

Ant.property(environment:"env")
grailsHome = Ant.antProject.properties."env.GRAILS_HOME"  

includeTargets << new File ( "${grailsHome}/scripts/RunApp.groovy" )

target (default: "Run's all of the Web tests against a Grails application") {
	depends( checkForTests, classpath, checkVersion, packagePlugins, packageApp, generateWebXml )
    event("StatusUpdate", [ "Running WebTest"])

	Ant.property(file:'./webtest/conf/webtest.properties')
	def serverPort = Ant.antProject.properties.'webtest_port'	
	runApp.serverPort = serverPort.toInteger()
    
    def failed = false
	try {
	    failed = runWebTest()
        event("StatusFinal", [ "WebTest complete"])
    } catch (Throwable t) {
    	failed = true        
        event("StatusError", [ "${t.class.name}: $t.message"])
        event("StatusFinal", [ "WebTest error occurred"])
        throw t
    }
    finally {
        stopServer()
        if (failed) {
        	exit(1)
        }
    }
}

/** @return true when failed, false if successful %-/ **/
target ( runWebTest : "Main implementation that executes a Grails' Web tests") {
	depends( runApp )

	String testfile = args.trim() ?: 'TestSuite'

    Ant.ant(antfile:"${webtestPluginDir}/scripts/call-webtest.xml"){
        property(name:'pluginHome', value: webtestPluginDir)
        property(name:'grailsHome', value: grailsHome)
		  property(name:'testfile', value: "${testfile}.groovy")
    }


    // Load the result file and determine whether any of the tests failed.
    File webtestPropFile = new File("${basedir}/webtest/conf/webtest.properties")    
    Properties props = new Properties()
    props.load(webtestPropFile.newInputStream())

    File resultFile = new File("$props.webtest_resultpath/$props.webtest_resultfile")
    if (! resultFile.exists()) return true
	def xml = new XmlSlurper().parse(resultFile)
	return xml.folder.summary.topsteps.@failed.text().toList()*.toInteger().sum() != 0
}

target ( checkForTests : "Checks that there are WebTests to run and fails if not"){
    def tests = resolveResources("file:${basedir}/webtest/tests/**/*")
    if(!tests){
        Ant.fail("WARNING: This project does not contain any WebTests.")
    }
}

