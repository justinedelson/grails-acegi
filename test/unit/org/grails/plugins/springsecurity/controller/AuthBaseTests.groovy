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
package org.grails.plugins.springsecurity.controller

import org.codehaus.groovy.grails.plugins.springsecurity.AbstractSecurityTest
import org.codehaus.groovy.grails.plugins.springsecurity.AuthorizeTools
import org.grails.plugins.springsecurity.service.AuthenticateService
import org.easymock.EasyMock
import org.springframework.mock.web.MockHttpServletRequestimport org.springframework.mock.web.MockHttpServletResponseimport org.springframework.security.Authentication
import org.springframework.security.GrantedAuthority
import org.springframework.web.servlet.DispatcherServlet
import org.springframework.web.servlet.LocaleResolver

/**
 * Unit tests for AuthBase.
 *
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
class AuthBaseTests extends AbstractSecurityTest {

	private final AuthBase _authBase = new AuthBase()
	private final AuthenticateService _service = new AuthenticateService()

	private final Map _redirectParams = [:]
	private final Map _params = [:]
	private final Map _session = [:]
	private final MockHttpServletRequest _request = new MockHttpServletRequest()
	private final MockHttpServletResponse _response = new MockHttpServletResponse()

	/**
	 * Test beforeInterceptor when not authenticated.
	 */
	void testBeforeInterceptorNotAuthenticated() {
		_authBase.requestAllowed = 'role1,role2'

		def redirectParams = [:]
		_authBase.metaClass.redirect = { Map m -> redirectParams = m }

		_authBase.beforeInterceptor()

		assertEquals '/', redirectParams.uri
	}

	/**
	 * Test beforeInterceptor when authenticated but insufficient roles.
	 */
	void testBeforeInterceptorMissingRole() {
		_authBase.requestAllowed = 'role1,role2'

		def redirectParams = [:]
		_authBase.metaClass.redirect = { Map m -> redirectParams = m }

		authenticate('role3')

		_authBase.beforeInterceptor()

		assertEquals '/', redirectParams.uri
	}

	/**
	 * Test beforeInterceptor when authenticated and with correct roles.
	 */
	void testBeforeInterceptorCorrectRoles() {
		_authBase.requestAllowed = 'role1,role2'

		def authentication = authenticate('role1,role2')

		wireUpMetaClassMethods()

		_authBase.beforeInterceptor()

		assertEquals 'not redirected', 0, _redirectParams.size()
		assertTrue _authBase.logon
		assertFalse _authBase.isAdmin
		assertEquals authentication.principal, _authBase.authPrincipal
		assertEquals authentication.principal.domainClass, _authBase.loginUser

		assertEquals(-1, _response.getHeader('Expires'))
		assertEquals 0, _response.getHeader('max-age')
		assertEquals 'no-cache', _response.getHeader('Cache-Control')
		assertEquals Locale.ENGLISH, _authBase.locale
	}

	/**
	 * Test beforeInterceptor when authenticated as admin.
	 */
	void testBeforeInterceptorAsAdmin() {
		_authBase.requestAllowed = 'role1,role2'

		def authentication = authenticate('role1,role2,ROLE_SUPERVISOR')

		wireUpMetaClassMethods()

		_authBase.beforeInterceptor()

		assertEquals 'not redirected', 0, _redirectParams.size()
		assertTrue _authBase.logon
		assertTrue _authBase.isAdmin
		assertEquals authentication.principal, _authBase.authPrincipal
		assertEquals authentication.principal.domainClass, _authBase.loginUser
	}

	/**
	 * Test beforeInterceptor when authenticated and with a Locale param.
	 */
	void testBeforeInterceptorLocaleParam() {
		_authBase.requestAllowed = 'role1,role2'

		def authentication = authenticate('role1,role2')

		wireUpMetaClassMethods()

		String localeName = 'foo'
		_params.lang = localeName

		LocaleResolver localeResolver = EasyMock.createMock(LocaleResolver)
		_request.setAttribute(DispatcherServlet.LOCALE_RESOLVER_ATTRIBUTE, localeResolver)
		localeResolver.setLocale(EasyMock.eq(_request), EasyMock.eq(_response), EasyMock.eq(new Locale(localeName)))
		EasyMock.expectLastCall().times(2)
		EasyMock.replay(localeResolver)

		_authBase.beforeInterceptor()

		assertEquals 'not redirected', 0, _redirectParams.size()
		assertTrue _authBase.logon
		assertEquals localeName, _session.lang

		EasyMock.verify(localeResolver)
	}

	/**
	 * Test beforeInterceptor when authenticated and with a session Locale name.
	 */
	void testBeforeInterceptorSessionLocale() {
		_authBase.requestAllowed = 'role1,role2'

		def authentication = authenticate('role1,role2')

		wireUpMetaClassMethods()

		String localeName = 'foo'
		_session.lang = localeName

		LocaleResolver localeResolver = EasyMock.createMock(LocaleResolver)
		_request.setAttribute(DispatcherServlet.LOCALE_RESOLVER_ATTRIBUTE, localeResolver)
		localeResolver.setLocale(EasyMock.eq(_request), EasyMock.eq(_response), EasyMock.eq(new Locale(localeName)))
		EasyMock.expectLastCall()
		EasyMock.replay(localeResolver)

		_authBase.beforeInterceptor()

		assertEquals 'not redirected', 0, _redirectParams.size()
		assertTrue _authBase.logon
		assertEquals localeName, _session.lang

		EasyMock.verify(localeResolver)
	}

	/**
	 * {@inheritDoc}
	 * @see junit.framework.TestCase#setUp()
	 */
	@Override
	protected void setUp() {
		super.setUp()
		_authBase.authenticateService = _service
	}

	private void wireUpMetaClassMethods() {
		_authBase.metaClass.redirect = { Map m -> _redirectParams = m }
		_authBase.metaClass.getParams = { -> _params }
		_authBase.metaClass.getSession = { -> _session }
		_authBase.metaClass.getRequest = { -> _request }
		_authBase.metaClass.getResponse = { -> _response }
	}

	protected Authentication authenticate(roles) {
		def principal = new Expando()
		principal.domainClass = new Expando()
		return authenticate(principal, null,
			AuthorizeTools.parseAuthoritiesString(roles) as GrantedAuthority[])
	}

	/**
	 * {@inheritDoc}
	 * @see junit.framework.TestCase#tearDown()
	 */
	@Override
	protected void tearDown() {
		super.tearDown()
		removeMetaClassMethods(AuthBase)
	}
}
