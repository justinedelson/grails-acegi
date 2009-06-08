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

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.util.PortResolver;
import org.springframework.security.util.PortResolverImpl;

/**
 * Fixes <a href='http://jira.codehaus.org/browse/GRAILSPLUGINS-273'>this redirect bug</a>.
 * @author Tsuyoshi Yamamoto
 */
public final class RedirectUtils {

	private static final PortResolver RESOLVER = new PortResolverImpl();

	private RedirectUtils() {
		// static only
	}

	/**
	 * Send a redirect.
	 * @param request  the request
	 * @param response  the response
	 * @param url the target url to redirect to
	 * @throws IOException  if there's a problem
	 */
	public static void sendRedirect(final HttpServletRequest request, final HttpServletResponse response,
			final String url) throws IOException {

		String redirect = buildRedirectUrl(request, response, url);
		response.sendRedirect(response.encodeRedirectURL(redirect));
	}

	/**
	 * Build a redirect url.
	 * @param request  the request
	 * @param response  the response
	 * @param url the target url to redirect to
	 * @return  the url
	 */
	public static String buildRedirectUrl(final HttpServletRequest request,
			final HttpServletResponse response, final String url) {

		if (!url.startsWith("http://") && !url.startsWith("https://")) {
			String scheme = request.getScheme();
			int serverPort = RESOLVER.getServerPort(request);
			boolean inHttp = "http".equalsIgnoreCase(scheme);
			boolean inHttps = "https".equalsIgnoreCase(scheme);
			boolean includePort = !((inHttp && serverPort == 80)  || (inHttps && serverPort == 443));
			String port = includePort ? ":" + serverPort : "";
			return scheme + "://" + request.getServerName() + port + request.getContextPath() + url;
		}

		return url;
	}
}
