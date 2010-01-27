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

import grails.test.ControllerUnitTestCase

import org.codehaus.groovy.grails.plugins.springsecurity.AuthorizeTools
import org.codehaus.groovy.grails.plugins.springsecurity.SecurityTestUtils
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
class AuthBaseTests extends ControllerUnitTestCase {

	private final AuthenticateService _service = new AuthenticateService()

	AuthBaseTests() {
		super(AuthBase)
	}

	/**
	 * Test beforeInterceptor when not authenticated.
	 */
	void testBeforeInterceptorNotAuthenticated() {
		controller.requestAllowed = 'role1,role2'

		controller.beforeInterceptor()

		assertEquals '/', redirectArgs.uri
	}

	/**
	 * Test beforeInterceptor when authenticated but insufficient roles.
	 */
	void testBeforeInterceptorMissingRole() {
		controller.requestAllowed = 'role1,role2'

		authenticate('role3')

		controller.beforeInterceptor()

		assertEquals '/', redirectArgs.uri
	}

	/**
	 * Test beforeInterceptor when authenticated and with correct roles.
	 */
	void testBeforeInterceptorCorrectRoles() {
		controller.requestAllowed = 'role1,role2'

		def authentication = authenticate('role1,role2')

		controller.beforeInterceptor()

		assertEquals 'not redirected', 0, redirectArgs.size()
		assertTrue controller.logon
		assertFalse controller.isAdmin
		assertEquals authentication.principal, controller.authPrincipal
		assertEquals authentication.principal.domainClass, controller.loginUser

		assertEquals Locale.ENGLISH, controller.locale
	}

	/**
	 * Test beforeInterceptor when authenticated as admin.
	 */
	void testBeforeInterceptorAsAdmin() {
		controller.requestAllowed = 'role1,role2'

		def authentication = authenticate('role1,role2,ROLE_SUPERVISOR')

		controller.beforeInterceptor()

		assertEquals 'not redirected', 0, redirectArgs.size()
		assertTrue controller.logon
		assertTrue controller.isAdmin
		assertEquals authentication.principal, controller.authPrincipal
		assertEquals authentication.principal.domainClass, controller.loginUser
	}

	/**
	 * Test beforeInterceptor when authenticated and with a Locale param.
	 */
	void testBeforeInterceptorLocaleParam() {
		controller.requestAllowed = 'role1,role2'

		def authentication = authenticate('role1,role2')

		String localeName = 'foo'
		mockParams.lang = localeName

		LocaleResolver localeResolver = EasyMock.createMock(LocaleResolver)
		mockRequest.setAttribute(DispatcherServlet.LOCALE_RESOLVER_ATTRIBUTE, localeResolver)
		localeResolver.setLocale(EasyMock.eq(mockRequest), EasyMock.eq(mockResponse), EasyMock.eq(new Locale(localeName)))
		EasyMock.expectLastCall().times(2)
		EasyMock.replay(localeResolver)

		controller.beforeInterceptor()

		assertEquals 'not redirected', 0, redirectArgs.size()
		assertTrue controller.logon
		assertEquals localeName, mockSession.lang

		EasyMock.verify(localeResolver)
	}

	/**
	 * Test beforeInterceptor when authenticated and with a session Locale name.
	 */
	void testBeforeInterceptorSessionLocale() {
		controller.requestAllowed = 'role1,role2'

		def authentication = authenticate('role1,role2')

		String localeName = 'foo'
		mockSession.lang = localeName

		LocaleResolver localeResolver = EasyMock.createMock(LocaleResolver)
		mockRequest.setAttribute(DispatcherServlet.LOCALE_RESOLVER_ATTRIBUTE, localeResolver)
		localeResolver.setLocale(EasyMock.eq(mockRequest), EasyMock.eq(mockResponse), EasyMock.eq(new Locale(localeName)))
		EasyMock.expectLastCall()
		EasyMock.replay(localeResolver)

		controller.beforeInterceptor()

		assertEquals 'not redirected', 0, redirectArgs.size()
		assertTrue controller.logon
		assertEquals localeName, mockSession.lang

		EasyMock.verify(localeResolver)
	}

	/**
	 * {@inheritDoc}
	 * @see junit.framework.TestCase#setUp()
	 */
	@Override
	protected void setUp() {
		super.setUp()
		controller.authenticateService = _service
	}

	/**
	 * {@inheritDoc}
	 * @see junit.framework.TestCase#tearDown()
	 */
	@Override
	protected void tearDown() {
		super.tearDown()
		SecurityTestUtils.logout()
	}

	private Authentication authenticate(roles) {
		def principal = new Expando()
		principal.domainClass = new Expando()
		return SecurityTestUtils.authenticate(principal, null,
			AuthorizeTools.parseAuthoritiesString(roles) as GrantedAuthority[])
	}
}
