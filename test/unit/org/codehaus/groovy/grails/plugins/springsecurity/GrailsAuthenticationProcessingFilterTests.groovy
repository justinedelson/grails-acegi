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

import javax.servlet.FilterChain
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

import org.easymock.EasyMock

import org.springframework.mock.web.MockFilterChain
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse

import org.springframework.security.AuthenticationCredentialsNotFoundException
import org.springframework.security.ui.webapp.AuthenticationProcessingFilter

/**
 * Unit tests for GrailsAuthenticationProcessingFilter.
 *
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
class GrailsAuthenticationProcessingFilterTests extends GrailsUnitTestCase {

	private final _filter = new GrailsAuthenticationProcessingFilter()
	private final _request = new MockHttpServletRequest('GET', '/foo/bar')
	private final _response = new MockHttpServletResponse()

	protected void setUp() {
		super.setUp()
		registerMetaClass SecurityRequestHolder
	}

	/**
	 * Test sendRedirect().
	 */
	void testSendRedirect() {

		String url = '/foo/bar'

		_filter.sendRedirect(_request, _response, url)

		assertEquals 'http://localhost/foo/bar', _response.redirectedUrl
	}

	/**
	 * Test doFilterHttp().
	 */
//	void testDoFilterHttp() {
//
//		HttpServletRequest srhRequest
//		HttpServletResponse srhResponse
//		boolean resetCalled = false
//
//		SecurityRequestHolder.metaClass.'static'.set = { HttpServletRequest req, HttpServletResponse res ->
//			srhRequest = req
//			srhResponse = res
//		}
//
//		SecurityRequestHolder.metaClass.'static'.reset = { ->
//			resetCalled = true
//		}
//
//		_filter.doFilterHttp _request, _response, new MockFilterChain()
//
//		assertSame _request, srhRequest
//		assertSame _response, srhResponse
//		assertTrue resetCalled
//	}

	void testDetermineFailureUrlAjax() {

		String ajaxAuthenticationFailureUrl = 'ajax_url'
		String authenticationFailureUrl = 'standard_url'

		_filter.ajaxAuthenticationFailureUrl = ajaxAuthenticationFailureUrl
		_filter.authenticationFailureUrl = authenticationFailureUrl

		AuthorizeTools.ajaxHeaderName = 'ajaxHeader'
		_request.addHeader('ajaxHeader', 'foo')

		assertEquals ajaxAuthenticationFailureUrl, _filter.determineFailureUrl(
				_request, new AuthenticationCredentialsNotFoundException(''))
	}

	void testDetermineFailureUrlNotAjax() {

		String ajaxAuthenticationFailureUrl = 'ajax_url'
		String authenticationFailureUrl = 'standard_url'

		_filter.ajaxAuthenticationFailureUrl = ajaxAuthenticationFailureUrl
		_filter.authenticationFailureUrl = authenticationFailureUrl

		AuthorizeTools.ajaxHeaderName = 'ajaxHeader'

		assertEquals authenticationFailureUrl, _filter.determineFailureUrl(
				_request, new AuthenticationCredentialsNotFoundException(''))
	}
}
