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
import java.util.Map;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Required;
import org.springframework.security.AccessDeniedException;
import org.springframework.security.ui.FilterChainOrder;
import org.springframework.security.ui.SpringSecurityFilter;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.Assert;

/**
 * Blocks access to protected resources based on IP address. Sends 404 rather than
 * reporting error to hide visibility of the resources.
 *
 * @author <a href='mailto:beckwithb@studentsonly.com'>Burt Beckwith</a>
 */
public class IpAddressFilter extends SpringSecurityFilter implements InitializingBean {

	private final Logger _log = Logger.getLogger(getClass());

	private final AntPathMatcher _pathMatcher = new AntPathMatcher();

	private Map<String, String> _restrictions;

	/**
	 * {@inheritDoc}
	 * @see org.springframework.security.ui.SpringSecurityFilter#doFilterHttp(
	 * 	javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse,
	 * 	javax.servlet.FilterChain)
	 */
	@Override
	protected void doFilterHttp(
			  final HttpServletRequest request,
			  final HttpServletResponse response,
			  final FilterChain chain) throws IOException, ServletException {

		if (!isAllowed(request.getRemoteAddr(), request.getRequestURI())) {
			_log.error("disallowed request " + request.getRequestURI()
					  + " from " + request.getRemoteAddr());
			// TODO  this doesn't work
//			response.sendError(HttpServletResponse.SC_NOT_FOUND);
//			return;
			throw new AccessDeniedException("Access is denied");
		}

		chain.doFilter(request, response);
	}

	/**
	 * {@inheritDoc}
	 * @see org.springframework.security.ui.SpringSecurityFilter#getOrder()
	 */
	public int getOrder() {
		return FilterChainOrder.LOGOUT_FILTER + 1;
	}

	/**
	 * {@inheritDoc}
	 * @see org.springframework.beans.factory.InitializingBean#afterPropertiesSet()
	 */
	public void afterPropertiesSet() {
		Assert.notNull(_restrictions, "ipRestrictions is required");
	}

	/**
	 * Dependency injection for the ip/pattern restriction map.
	 * @param restrictions  the map
	 */
	@Required
	public void setIpRestrictions(final Map<String, String> restrictions) {
		_restrictions = restrictions;
	}

	private boolean isAllowed(final String ip, final String requestURI) {

		if ("127.0.0.1".equals(ip)) {
			return true;
		}

		for (Map.Entry<String, String> entry : _restrictions.entrySet()) {
			String uriPattern = entry.getKey();
			String ipPattern = entry.getValue();
			if (_pathMatcher.match(uriPattern, requestURI)
					  && !_pathMatcher.match(ipPattern, ip)) {
				return false;
			}
		}

		return true;
	}
}
