/* Copyright 2006-2009 the original author or authors.
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
package org.codehaus.groovy.grails.plugins.springsecurity

import grails.test.GrailsUnitTestCase

import groovy.util.ConfigObject

import javax.servlet.ServletContext
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

import org.codehaus.groovy.grails.commons.ApplicationHolder
import org.codehaus.groovy.grails.commons.ConfigurationHolder as CH
import org.codehaus.groovy.grails.commons.DefaultGrailsApplication
import org.codehaus.groovy.grails.commons.DefaultGrailsControllerClass
import org.codehaus.groovy.grails.commons.GrailsApplication
import org.codehaus.groovy.grails.commons.GrailsClass
import org.codehaus.groovy.grails.commons.GrailsControllerClass
import org.codehaus.groovy.grails.web.context.ServletContextHolder
import org.codehaus.groovy.grails.web.mapping.DefaultUrlMappingEvaluator
import org.codehaus.groovy.grails.web.mapping.DefaultUrlMappingsHolder
import org.codehaus.groovy.grails.web.mapping.UrlMappingInfo
import org.codehaus.groovy.grails.web.mapping.UrlMappingsHolder
import org.codehaus.groovy.grails.web.servlet.mvc.GrailsWebRequest

import org.springframework.mock.web.MockFilterChain
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse
import org.springframework.mock.web.MockServletContext
import org.springframework.security.ConfigAttributeDefinition;
import org.springframework.security.intercept.web.FilterInvocation
import org.springframework.security.util.AntUrlPathMatcherimport org.springframework.util.Assert
import org.springframework.web.context.WebApplicationContext
import org.springframework.web.context.request.RequestContextHolder
import org.springframework.web.context.support.WebApplicationContextUtils

/**
 * Unit tests for AnnotationFilterInvocationDefinition.
 *
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
class AnnotationFilterInvocationDefinitionTests extends GrailsUnitTestCase {

	private _fid
	private _application

	/**
	 * {@inheritDoc}
	 * @see junit.framework.TestCase#setUp()
	 */
	@Override
	protected void setUp() {
		super.setUp()
		_application = ApplicationHolder.application
		_fid = new AnnotationFilterInvocationDefinition()
	}

	void testSupports() {
		assertTrue _fid.supports(FilterInvocation)
	}

	void testGetConfigAttributeDefinitions() {
		assertNull _fid.configAttributeDefinitions
	}

	void testLowercaseAndStripQuerystring() {
		_fid.urlMatcher = new AntUrlPathMatcher()

		assertEquals '/foo/bar', _fid.lowercaseAndStripQuerystring('/foo/BAR')
		assertEquals '/foo/bar', _fid.lowercaseAndStripQuerystring('/foo/bar')
		assertEquals '/foo/bar', _fid.lowercaseAndStripQuerystring('/foo/BAR?x=1')
	}

	void testGetAttributesNull() {
		shouldFail(IllegalArgumentException) {
			_fid.getAttributes null
		}
	}

	void testGetAttributesNotSupports() {
		shouldFail(IllegalArgumentException) {
			_fid.getAttributes 'foo'
		}
	}

	void testGetAttributes() {
		def request = new MockHttpServletRequest()
		def response = new MockHttpServletResponse()
		def chain = new MockFilterChain()
		FilterInvocation filterInvocation = new FilterInvocation(request, response, chain)

		def matcher = new AntUrlPathMatcher()

		_fid = new MockAnnotationFilterInvocationDefinition(null)
		_fid.urlMatcher = matcher

		String pattern = '/foo/**'
		def configAttribute = new ConfigAttributeDefinition(['ROLE_ADMIN'] as String[])
		_fid.@_compiled.put matcher.compile(pattern), configAttribute

		request.requestURI = '/foo/bar'
		_fid._url = request.requestURI
		assertEquals configAttribute, _fid.getAttributes(filterInvocation)

		_fid.rejectIfNoRule = false
		request.requestURI = '/bar/foo'
		_fid._url = request.requestURI
		assertNull _fid.getAttributes(filterInvocation)

		_fid.rejectIfNoRule = true
		assertEquals AbstractFilterInvocationDefinition.DENY, _fid.getAttributes(filterInvocation)

		String moreSpecificPattern = '/foo/ba*'
		def moreSpecificConfigAttribute = new ConfigAttributeDefinition(['ROLE_SUPERADMIN'] as String[])
		_fid.@_compiled.put matcher.compile(moreSpecificPattern), moreSpecificConfigAttribute

		request.requestURI = '/foo/bar'
		_fid._url = request.requestURI
		assertEquals moreSpecificConfigAttribute, _fid.getAttributes(filterInvocation)
	}

	void testDetermineUrl_StaticRequest() {
		def request = new MockHttpServletRequest()
		def response = new MockHttpServletResponse()
		def filterChain = new MockFilterChain()

		request.requestURI = 'requestURI'

		_fid = new MockAnnotationFilterInvocationDefinition(null)
		_fid.urlMatcher = new AntUrlPathMatcher()

		FilterInvocation filterInvocation = new FilterInvocation(request, response, filterChain)

		AnnotationFilterInvocationDefinition.metaClass.findGrailsUrl = { req, res, String url -> null }

		assertEquals 'requesturi', _fid.determineUrl(filterInvocation)
	}

	void testDetermineUrl_DynamicRequest() {
		def request = new MockHttpServletRequest()
		def response = new MockHttpServletResponse()
		def filterChain = new MockFilterChain()

		request.requestURI = 'requestURI'

		_fid = new MockAnnotationFilterInvocationDefinition('FOO?x=1')
		_fid.urlMatcher = new AntUrlPathMatcher()

		FilterInvocation filterInvocation = new FilterInvocation(request, response, filterChain)

		AnnotationFilterInvocationDefinition.metaClass.findGrailsUrl = { req, res, String url -> null }

		assertEquals 'foo', _fid.determineUrl(filterInvocation)
	}

	void testFindGrailsUrl() {
		def application = new TestApplication()
		ApplicationHolder.application = application
		def request = new MockHttpServletRequest()
		def response = new MockHttpServletResponse()
		def servletContext = new MockServletContext()
		ServletContextHolder.servletContext = servletContext

		def existingRequest = new GrailsWebRequest(request, response, servletContext)
		RequestContextHolder.setRequestAttributes(existingRequest, false)

		UrlMappingInfo[] mappings = [[getControllerName: { -> 'foo' },
		                              getActionName: { -> 'bar' },
		                              configure: { GrailsWebRequest r -> }] as UrlMappingInfo]
		_fid.@_urlMappingsHolder = [matchAll: { String uri -> mappings }] as UrlMappingsHolder

		assertEquals '/foo/bar', _fid.findGrailsUrl(request, response, 'request_url')
	}

	void testInitialize() {

		def mappings = {

			"/admin/user/$action?/$id?"(controller: "adminUser")

			"/$controller/$action?/$id?" { constraints {} }

	      "/"(view:"/index")

			/**** Error Mappings ****/

			"403"(controller: "errors", action: "accessDenied")
			"404"(controller: "errors", action: "notFound")
			"405"(controller: "errors", action: "notAllowed")
			"500"(view: '/error')
		}

		ServletContext servletContext = new MockServletContext()
		ConfigObject config = new ConfigObject()
		CH.config = config

		def app = new DefaultGrailsApplication()
		def beans = [(GrailsApplication.APPLICATION_ID): app]
		def ctx = [getBean: { String name -> beans[name] }] as WebApplicationContext
		servletContext.setAttribute WebApplicationContext.ROOT_WEB_APPLICATION_CONTEXT_ATTRIBUTE, ctx

		def mappingEvaluator = new DefaultUrlMappingEvaluator(servletContext)

		def urlMappingsHolder = new DefaultUrlMappingsHolder(
				mappings.collect { mappingEvaluator.evaluateMappings(mappings) }.flatten())

		Map<String, Collection<String>> staticRules = ['/js/admin/**': ['ROLE_ADMIN']]
		GrailsClass[] controllerClasses = [new DefaultGrailsControllerClass(ClassAnnotatedController),
		                                   new DefaultGrailsControllerClass(MethodAnnotatedController)]

		_fid.urlMatcher = new AntUrlPathMatcher()

		_fid.initialize(staticRules, urlMappingsHolder, controllerClasses)

		assertEquals 4, _fid.@_compiled.size()

		def configAttributeDefinition

		configAttributeDefinition = _fid.@_compiled['/classannotated/**']
		assertEquals 1, configAttributeDefinition.configAttributes.size()
		assertEquals 'ROLE_ADMIN', configAttributeDefinition.configAttributes[0].attribute

		configAttributeDefinition = _fid.@_compiled['/classannotated/list/**']
		assertEquals 2, configAttributeDefinition.configAttributes.size()
		assertEquals(['ROLE_FOO', 'ROLE_SUPERADMIN'] as Set,
			configAttributeDefinition.configAttributes*.attribute as Set)

		configAttributeDefinition = _fid.@_compiled['/methodannotated/list/**']
		assertEquals 1, configAttributeDefinition.configAttributes.size()
		assertEquals 'ROLE_ADMIN', configAttributeDefinition.configAttributes[0].attribute

		configAttributeDefinition = _fid.@_compiled['/js/admin/**']
		assertEquals 1, configAttributeDefinition.configAttributes.size()
		assertEquals 'ROLE_ADMIN', configAttributeDefinition.configAttributes[0].attribute
	}

	void testFindConfigAttribute() {

		def matcher = new AntUrlPathMatcher()

		_fid.urlMatcher = matcher

		String pattern = '/foo/**'
		def configAttribute = new ConfigAttributeDefinition(['ROLE_ADMIN'] as String[])
		_fid.@_compiled.put matcher.compile(pattern), configAttribute

		assertEquals configAttribute, _fid.findConfigAttribute('/foo/bar')
		assertNull _fid.findConfigAttribute('/bar/foo')
	}

	/**
	 * {@inheritDoc}
	 * @see junit.framework.TestCase#tearDown()
	 */
	@Override
	protected void tearDown() {
		super.tearDown()
		ApplicationHolder.application = _application
		RequestContextHolder.resetRequestAttributes()
		ServletContextHolder.servletContext = null
		CH.config = null
	}
}

class TestApplication extends DefaultGrailsApplication {
	GrailsClass getArtefactForFeature(String artefactType, Object featureID) {
		return [:] as GrailsClass
	}
}

class MockAnnotationFilterInvocationDefinition extends AnnotationFilterInvocationDefinition {

	String _url

	MockAnnotationFilterInvocationDefinition(String url) {
		_url = url
	}

	protected String findGrailsUrl(HttpServletRequest request, HttpServletResponse response, String requestUrl) {
		_url
	}
}

@Secured(['ROLE_ADMIN'])
class ClassAnnotatedController {

	def index = {}

	@Secured(['ROLE_SUPERADMIN', 'ROLE_FOO'])
	def list = { [results: []] }
}

class MethodAnnotatedController {

	def index = {}

	@Secured(['ROLE_ADMIN'])
	def list = { [results: []] }
}
