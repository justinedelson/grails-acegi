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
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.FactoryBean;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.ui.logout.LogoutFilter;
import org.springframework.security.ui.logout.LogoutHandler;
import org.springframework.util.Assert;

/**
 * Configures a {@link LogoutFilter} given a list of {@link LogoutHandler}s.
 *
 * @author <a href='mailto:beckwithb@studentsonly.com'>Burt Beckwith</a>
 */
public class LogoutFilterFactoryBean implements FactoryBean, InitializingBean {

	private List<LogoutHandler> _handlers;
	private LogoutFilter _logoutFilter;
	private String _logoutSuccessUrl;
	private String _filterProcessesUrl;
	private boolean _useRelativeContext;

	/**
	 * {@inheritDoc}
	 * @see org.springframework.beans.factory.FactoryBean#getObject()
	 */
	public LogoutFilter getObject() {
		return _logoutFilter;
	}

	/**
	 * {@inheritDoc}
	 * @see org.springframework.beans.factory.FactoryBean#getObjectType()
	 */
	public Class<LogoutFilter> getObjectType() {
		return LogoutFilter.class;
	}

	/**
	 * {@inheritDoc}
	 * @see org.springframework.beans.factory.FactoryBean#isSingleton()
	 */
	public boolean isSingleton() {
		return true;
	}

	/**
	 * {@inheritDoc}
	 * @see org.springframework.beans.factory.InitializingBean#afterPropertiesSet()
	 */
	public void afterPropertiesSet() {
		Assert.notNull(_logoutSuccessUrl, "logoutSuccessUrl is required");
		Assert.notNull(_handlers, "handlers are required");

		_logoutFilter = new LogoutFilter(_logoutSuccessUrl, _handlers.toArray(new LogoutHandler[_handlers.size()])) {
			@Override
			protected void sendRedirect(final HttpServletRequest request, final HttpServletResponse response,
					final String url) throws IOException {
				RedirectUtils.sendRedirect(request, response, url);
			}
		};

		_logoutFilter.setFilterProcessesUrl(_filterProcessesUrl);
		_logoutFilter.setUseRelativeContext(_useRelativeContext);
	}

	/**
	 * Dependency injection for the logout success url.
	 * @param url  the url
	 */
	public void setLogoutSuccessUrl(final String url) {
		_logoutSuccessUrl = url;
	}

	/**
	 * Dependency injection for 'filterProcessesUrl.
	 * @param url  the url
	 */
   public void setFilterProcessesUrl(final String url) {
   	_filterProcessesUrl = url;
   }

   /**
	 * Dependency injection for 'useRelativeContext.
	 * @param use  if <code>true</code> use relative context
	 */
   public void setUseRelativeContext(final boolean use) {
   	_useRelativeContext = use;
   }

	/**
	 * Dependency injection for the handlers.
	 * @param handlers  the handlers
	 */
	public void setHandlers(final List<LogoutHandler> handlers) {
		_handlers = handlers;
	}
}
