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
package org.codehaus.groovy.grails.plugins.springsecurity;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.AuthenticationException;
import org.springframework.security.ui.webapp.AuthenticationProcessingFilter;
import org.springframework.util.StringUtils;

/**
 * Extends the default {@link AuthenticationProcessingFilter} to override the <code>sendRedirect()</code>
 * logic and always send absolute redirects.
 *
 * @author Tsuyoshi Yamamoto
 */
public class GrailsAuthenticationProcessingFilter extends AuthenticationProcessingFilter {

	private String _ajaxAuthenticationFailureUrl;

	/**
	 * {@inheritDoc}
	 * @see org.springframework.security.ui.AbstractProcessingFilter#doFilterHttp(
	 * 	javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse,
	 * 	javax.servlet.FilterChain)
	 */
	@Override
	public void doFilterHttp(final HttpServletRequest request, final HttpServletResponse response,
			final FilterChain chain) throws IOException, ServletException {

		SecurityRequestHolder.set(request, response);
		try {
			super.doFilterHttp(request, response, chain);
		}
		finally {
			SecurityRequestHolder.reset();
		}
	}

	/**
	 * {@inheritDoc}
	 * @see org.springframework.security.ui.AbstractProcessingFilter#sendRedirect(
	 * 	javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse,
	 * 	java.lang.String)
	 */
	@Override
	protected void sendRedirect(final HttpServletRequest request, final HttpServletResponse response,
			final String url) throws IOException {
		RedirectUtils.sendRedirect(request, response, url);
	}

	/**
	 * {@inheritDoc}
	 * @see org.springframework.security.ui.AbstractProcessingFilter#determineFailureUrl(
	 * 	javax.servlet.http.HttpServletRequest, org.springframework.security.AuthenticationException)
	 */
	@Override
	protected String determineFailureUrl(final HttpServletRequest request, final AuthenticationException failed) {
		String url = super.determineFailureUrl(request, failed);
		if (getAuthenticationFailureUrl().equals(url) && AuthorizeTools.isAjax(request)) {
			url = StringUtils.hasLength(_ajaxAuthenticationFailureUrl)
				? _ajaxAuthenticationFailureUrl
				: getAuthenticationFailureUrl();
		}
		return url;
	}

	/**
	 * Dependency injection for the Ajax auth fail url.
	 * @param url  the url
	 */
	public void setAjaxAuthenticationFailureUrl(final String url) {
		_ajaxAuthenticationFailureUrl = url;
	}
}
