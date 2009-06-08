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

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.codehaus.groovy.grails.commons.ApplicationHolder;
import org.hibernate.SessionFactory;
import org.springframework.beans.BeanWrapper;
import org.springframework.beans.BeanWrapperImpl;
import org.springframework.security.ConfigAttributeDefinition;
import org.springframework.security.intercept.web.FilterInvocation;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
public class RequestmapFilterInvocationDefinition extends AbstractFilterInvocationDefinition {

	private boolean _initialized;

	private String _requestMapClassName;
	private String _requestMapPathFieldName;
	private String _requestMapConfigAttributeFieldName;
	private Method _getPath;
	private Method _getConfigAttribute;
	private Class<?> _requestmapClass;
	private SessionFactory _sessionFactory;

	@Override
	protected String determineUrl(final FilterInvocation filterInvocation) {
		HttpServletRequest request = filterInvocation.getHttpRequest();
		String requestUrl = request.getRequestURI().substring(request.getContextPath().length());
		return lowercaseAndStripQuerystring(requestUrl);
	}

	@Override
	protected void initialize() throws IllegalAccessException, InvocationTargetException {
		if (!_initialized) {
			reset();
			_initialized = true;
		}
	}

	/**
	 * Call at startup or when <code>Requestmap</code> instances have been added, removed, or changed.
	 * @throws InvocationTargetException  if there's a problem with reflection
	 * @throws IllegalAccessException  if there's a problem with reflection
	 */
	@Override
	public synchronized void reset() throws IllegalAccessException, InvocationTargetException {
		Map<String, String> data = loadRequestmaps();
		_compiled.clear();

		for (Map.Entry<String, String> entry : data.entrySet()) {
			String pattern = entry.getKey();
			String[] tokens = split(entry.getValue());
			storeMapping(pattern, tokens);
		}

		if (_log.isTraceEnabled()) {
			_log.trace("configs: " + _compiled);
		}
	}

	// fixes extra spaces, trailing commas, etc.
	private String[] split(final String value) {
		String[] parts = StringUtils.commaDelimitedListToStringArray(value);
		List<String> cleaned = new ArrayList<String>();
		for (String part : parts) {
			part = part.trim();
			if (part.length() > 0) {
				cleaned.add(part);
			}
		}
		return cleaned.toArray(new String[cleaned.size()]);
	}

	private void storeMapping(final String pattern, final String[] tokens) {

		ConfigAttributeDefinition configAttribute = new ConfigAttributeDefinition(tokens);

		Object key = getUrlMatcher().compile(pattern);

		ConfigAttributeDefinition replaced = _compiled.put(key, configAttribute);
		if (replaced != null) {
			_log.warn("replaced rule for '" + key + "' with roles " + replaced.getConfigAttributes()
					+ " with roles " + configAttribute.getConfigAttributes());
		}
	}

	protected Map<String, String> loadRequestmaps() throws IllegalAccessException, InvocationTargetException {
		Map<String, String> data = new HashMap<String, String>();

		for (Object requestmap : _sessionFactory.openSession().createQuery("FROM " + _requestMapClassName).list()) {
			String urlPattern = (String)_getPath.invoke(requestmap);
			String configAttribute = (String)_getConfigAttribute.invoke(requestmap);
			data.put(urlPattern, configAttribute);
		}

		return data;
	}

	/**
	 * Dependency injection for the Requestmap class name.
	 * @param name  the class name
	 */
	public void setRequestMapClass(final String name) {
		_requestMapClassName = name;
	}

	/**
	 * Dependency injection for the Requestmap config attribute (e.g. roles) field name.
	 * @param name
	 */
	public void setRequestMapConfigAttributeField(final String name) {
		_requestMapConfigAttributeFieldName = name;
	}

	/**
	 * Dependency injection for the Requestmap path field name.
	 * @param name
	 */
	public void setRequestMapPathFieldName(final String name) {
		_requestMapPathFieldName = name;
	}

	/**
	 * Dependency injection for the {@link SessionFactory}.
	 * @param sessionFactory  the session factory
	 */
	public void setSessionFactory(final SessionFactory sessionFactory) {
		_sessionFactory = sessionFactory;
	}

	/**
	 * {@inheritDoc}
	 * @see org.springframework.beans.factory.InitializingBean#afterPropertiesSet()
	 */
	@Override
	public void afterPropertiesSet() {
		super.afterPropertiesSet();
		Assert.notNull(_requestMapClassName, "Requestmap class name is required");
		Assert.notNull(_requestMapPathFieldName, "Requestmap path field name is required");
		Assert.notNull(_requestMapConfigAttributeFieldName, "Requestmap config attribute field name is required");
		Assert.notNull(_sessionFactory, "sessionFactory is required");

		findGetters();
	}

	private void findGetters() {
		if (_requestmapClass == null) {
			_requestmapClass = ApplicationHolder.getApplication().getClassForName(_requestMapClassName);
		}
		BeanWrapper wrapper = new BeanWrapperImpl(_requestmapClass);
		_getPath = wrapper.getPropertyDescriptor(_requestMapPathFieldName).getReadMethod();
		_getConfigAttribute = wrapper.getPropertyDescriptor(_requestMapConfigAttributeFieldName).getReadMethod();
	}
}
