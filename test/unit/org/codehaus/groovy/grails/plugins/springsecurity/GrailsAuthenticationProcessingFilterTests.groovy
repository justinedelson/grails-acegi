package org.codehaus.groovy.grails.plugins.springsecurity

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
 * @author <a href='mailto:beckwithb@studentsonly.com'>Burt Beckwith</a>
 */
class GrailsAuthenticationProcessingFilterTests extends AbstractSecurityTest {

	private final GrailsAuthenticationProcessingFilter _filter = new GrailsAuthenticationProcessingFilter()
	private final MockHttpServletRequest _request = new MockHttpServletRequest('GET', '/foo/bar')
	private final MockHttpServletResponse _response = new MockHttpServletResponse()

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
	void testDoFilterHttp() {

		HttpServletRequest srhRequest
		boolean resetCalled = false

		SecurityRequestHolder.metaClass.'static'.setRequest = { req ->
			srhRequest = req
		}

		SecurityRequestHolder.metaClass.'static'.reset = { ->
			resetCalled = true
		}

		_filter.doFilterHttp _request, _response, new MockFilterChain()

		assertSame _request, srhRequest
		assertTrue resetCalled
	}

	void testDetermineFailureUrlAjax() {

		String ajaxAuthenticationFailureUrl = 'ajax_url'
		String authenticationFailureUrl = 'standard_url'

		_filter.ajaxAuthenticationFailureUrl = ajaxAuthenticationFailureUrl
		_filter.authenticationFailureUrl = authenticationFailureUrl
		_filter.authenticateService = [isAjax: { req -> true }]

		assertEquals ajaxAuthenticationFailureUrl, _filter.determineFailureUrl(
				_request, new AuthenticationCredentialsNotFoundException(''))
	}

	void testDetermineFailureUrlNotAjax() {

		String ajaxAuthenticationFailureUrl = 'ajax_url'
		String authenticationFailureUrl = 'standard_url'

		_filter.ajaxAuthenticationFailureUrl = ajaxAuthenticationFailureUrl
		_filter.authenticationFailureUrl = authenticationFailureUrl
		_filter.authenticateService = [isAjax: { req -> false }]

		assertEquals authenticationFailureUrl, _filter.determineFailureUrl(
				_request, new AuthenticationCredentialsNotFoundException(''))
	}

	/**
	 * {@inheritDoc}
	 * @see junit.framework.TestCase#tearDown()
	 */
	@Override
	protected void tearDown() {
		super.tearDown()
		removeMetaClassMethods AuthenticationProcessingFilter, SecurityRequestHolder
	}
}
