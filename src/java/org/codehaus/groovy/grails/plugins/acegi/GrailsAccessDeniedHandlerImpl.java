/* Copyright 2007 the original author or authors.
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
package org.codehaus.groovy.grails.plugins.acegi;

import org.acegisecurity.AccessDeniedException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.IOException;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.acegisecurity.ui.AccessDeniedHandler;
import org.acegisecurity.ui.AccessDeniedHandlerImpl;
import org.acegisecurity.util.PortResolver;
import org.acegisecurity.util.PortResolverImpl;

/**
 * AccessDeniedHandler for redirect to errorPage. (not RequestDispatcher#forward)
 * @author  T.Yamamoto
 */
public class GrailsAccessDeniedHandlerImpl implements AccessDeniedHandler {
	protected static final Log logger = LogFactory.getLog(GrailsAccessDeniedHandlerImpl.class);
	private String errorPage;
	private PortResolver portResolver = new PortResolverImpl();

	public void handle(ServletRequest request, ServletResponse response, AccessDeniedException accessDeniedException)
		throws IOException, ServletException {
		if (errorPage != null) {
			HttpServletRequest req = (HttpServletRequest) request;
			boolean includePort = true;
			String scheme = request.getScheme();
			String serverName = request.getServerName();
			int serverPort = portResolver.getServerPort(request);
			String contextPath = req.getContextPath();
			//String redirectUrl = "http://127.0.0.1:8080/simpletest/login/denied";
			boolean inHttp = "http".equals(scheme.toLowerCase());
			boolean inHttps = "https".equals(scheme.toLowerCase());
			
			if (inHttp && (serverPort == 80)) {
				includePort = false;
			}
			else if (inHttps && (serverPort == 443)) {
				includePort = false;
			}
			
			String redirectUrl = scheme + "://" + serverName + ((includePort) ? (":" + serverPort) : "") + contextPath + errorPage;
			((HttpServletResponse) response).sendRedirect(((HttpServletResponse) response).encodeRedirectURL(redirectUrl));
		}

		if (!response.isCommitted()) {
			// Send 403 (we do this after response has been written)
			((HttpServletResponse) response).sendError(HttpServletResponse.SC_FORBIDDEN, accessDeniedException.getMessage());
		}
	}

	public void setErrorPage(String errorPage) {
		if ((errorPage != null) && !errorPage.startsWith("/")) {
			throw new IllegalArgumentException("ErrorPage must begin with '/'");
		}
		this.errorPage = errorPage;
	}
}
