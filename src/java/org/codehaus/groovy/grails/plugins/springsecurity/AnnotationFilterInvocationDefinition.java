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

import java.lang.reflect.Field;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.WordUtils;
import org.apache.log4j.Logger;
import org.codehaus.groovy.grails.commons.ApplicationHolder;
import org.codehaus.groovy.grails.commons.ControllerArtefactHandler;
import org.codehaus.groovy.grails.commons.GrailsApplication;
import org.codehaus.groovy.grails.commons.GrailsClass;
import org.codehaus.groovy.grails.commons.GrailsControllerClass;
import org.codehaus.groovy.grails.web.context.ServletContextHolder;
import org.codehaus.groovy.grails.web.mapping.UrlMappingInfo;
import org.codehaus.groovy.grails.web.mapping.UrlMappingsHolder;
import org.codehaus.groovy.grails.web.servlet.mvc.GrailsParameterMap;
import org.codehaus.groovy.grails.web.servlet.mvc.GrailsWebRequest;
import org.codehaus.groovy.grails.web.util.WebUtils;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.ConfigAttributeDefinition;
import org.springframework.security.intercept.web.FilterInvocation;
import org.springframework.security.intercept.web.FilterInvocationDefinitionSource;
import org.springframework.security.util.AntUrlPathMatcher;
import org.springframework.security.util.UrlMatcher;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * A {@link FilterInvocationDefinitionSource} that uses rules defined with Controller annotations
 * combined with static rules defined in <code>SecurityConfig.groovy</code>, e.g. for js, images, css
 * or for rules that cannot be expressed in a controller like '/**'.
 *
 * @author <a href='mailto:beckwithb@studentsonly.com'>Burt Beckwith</a>
 */
public class AnnotationFilterInvocationDefinition
       implements FilterInvocationDefinitionSource, InitializingBean {

	private static final ConfigAttributeDefinition DENY =
		new ConfigAttributeDefinition(Collections.emptyList());

	private final Map<Object, ConfigAttributeDefinition> _compiled =
		new HashMap<Object, ConfigAttributeDefinition>();

	private final Logger _log = Logger.getLogger(getClass());

	private UrlMatcher _urlMatcher;
	private boolean _stripQueryStringFromUrls;
	private UrlMappingsHolder _urlMappingsHolder;
	private boolean _rejectIfNoRule;

	/**
	 * {@inheritDoc}
	 * @see org.springframework.security.intercept.ObjectDefinitionSource#getAttributes(java.lang.Object)
	 */
	public ConfigAttributeDefinition getAttributes(Object object) {
		if (object == null || !supports(object.getClass())) {
			throw new IllegalArgumentException("Object must be a FilterInvocation");
		}

		FilterInvocation filterInvocation = (FilterInvocation)object;

		String url = determineUrl(filterInvocation);

		ConfigAttributeDefinition configAttribute = findConfigAttribute(url);
		if (configAttribute == null && _rejectIfNoRule) {
			return DENY;
		}

		return configAttribute;
	}

	private String determineUrl(final FilterInvocation filterInvocation) {
		HttpServletRequest request = filterInvocation.getHttpRequest();
		HttpServletResponse response = filterInvocation.getHttpResponse();
		ServletContext servletContext = ServletContextHolder.getServletContext();
		GrailsApplication application = ApplicationHolder.getApplication();

		GrailsWebRequest existingRequest = WebUtils.retrieveGrailsWebRequest();

		String requestUrl = filterInvocation.getRequestUrl();

		String url = null;
		try {
			GrailsWebRequest grailsRequest = new GrailsWebRequest(request, response, servletContext);
			WebUtils.storeGrailsWebRequest(grailsRequest);

			Map<String, Object> savedParams = copyParams(grailsRequest);

			for (UrlMappingInfo mapping : _urlMappingsHolder.matchAll(requestUrl)) {
				configureMapping(mapping, grailsRequest, savedParams);

				url = findGrailsUrl(mapping, application);
				if (url != null) {
					break;
				}
			}
		}
		finally {
			if (existingRequest == null) {
				WebUtils.clearGrailsWebRequest();
			}
			else {
				WebUtils.storeGrailsWebRequest(existingRequest);
			}
		}

		if (!StringUtils.hasLength(url)) {
			// probably css/js/image
			url = requestUrl;
		}

		if (_urlMatcher.requiresLowerCaseUrl()) {
			url = url.toLowerCase();
		}

		if (_stripQueryStringFromUrls) {
			int firstQuestionMarkIndex = url.indexOf("?");
			if (firstQuestionMarkIndex != -1) {
				url = url.substring(0, firstQuestionMarkIndex);
			}
		}

		return url;
	}

	private String findGrailsUrl(final UrlMappingInfo mapping, final GrailsApplication application) {

		String actionName = mapping.getActionName();
		if (!StringUtils.hasLength(actionName)) {
			actionName = "";
		}

		String controllerName = mapping.getControllerName();

		if (isController(controllerName, actionName, application)) {
			if (!StringUtils.hasLength(actionName) || "null".equals(actionName)) {
				actionName = "index";
			}
			return ("/" + controllerName + "/" + actionName).trim();
		}

		return null;
	}

	private boolean isController(final String controllerName, final String actionName,
			final GrailsApplication application) {
		return application.getArtefactForFeature(ControllerArtefactHandler.TYPE,
				"/" + controllerName + "/" + actionName) != null;
	}

	private void configureMapping(final UrlMappingInfo mapping, final GrailsWebRequest grailsRequest,
			final Map<String, Object> savedParams) {

		// reset params since mapping.configure() sets values
		GrailsParameterMap params = grailsRequest.getParams();
		params.clear();
		params.putAll(savedParams);

		mapping.configure(grailsRequest);
	}

	private ConfigAttributeDefinition findConfigAttribute(final String url) {
		ConfigAttributeDefinition configAttribute = null;
		Object configAttributePattern = null;

		for (Map.Entry<Object, ConfigAttributeDefinition> entry : _compiled.entrySet()) {
			Object pattern = entry.getKey();
			if (_urlMatcher.pathMatchesUrl(pattern, url)) {
				// TODO  this assumes Ant matching, not valid for regex
				if (configAttribute == null || _urlMatcher.pathMatchesUrl(configAttributePattern, (String)pattern)) {
					configAttribute = entry.getValue();
					configAttributePattern = pattern;
					if (_log.isTraceEnabled()) {
						_log.trace("new candidate for '" + url + "': '" + pattern
								+ "':" + configAttribute.getConfigAttributes());
					}
				}
			}
		}

		if (_log.isTraceEnabled()) {
			if (configAttribute == null) {
				_log.trace("no config for '" + url + "'");
			}
			else {
				_log.trace("config for '" + url + "' is '" + configAttributePattern
						+ "':" + configAttribute.getConfigAttributes());
			}
		}

		return configAttribute;
	}

	@SuppressWarnings("unchecked")
	private Map<String, Object> copyParams(final GrailsWebRequest grailsRequest) {
		return new HashMap<String, Object>(grailsRequest.getParams());
	}

	/**
	 * {@inheritDoc}
	 * @see org.springframework.security.intercept.ObjectDefinitionSource#supports(java.lang.Class)
	 */
	@SuppressWarnings("unchecked")
	public boolean supports(final Class clazz) {
		return FilterInvocation.class.isAssignableFrom(clazz);
	}

	/**
	 * {@inheritDoc}
	 * @see org.springframework.security.intercept.ObjectDefinitionSource#getConfigAttributeDefinitions()
	 */
	@SuppressWarnings("unchecked")
	public Collection getConfigAttributeDefinitions() {
		return null;
	}

	/**
	 * Dependency injection for the url matcher.
	 * @param urlMatcher  the matcher
	 */
	public void setUrlMatcher(final UrlMatcher urlMatcher) {
		_urlMatcher = urlMatcher;
		_stripQueryStringFromUrls = _urlMatcher instanceof AntUrlPathMatcher;
	}

	/**
	 * Dependency injection for whether to reject if there's no matching rule.
	 * @param reject  if true, reject access unless there's a pattern for the specified resource
	 */
	public void setRejectIfNoRule(final boolean reject) {
		_rejectIfNoRule = reject;
	}

	/**
	 * Called by the plugin to set controller role info.<br/>
	 *
	 * Reinitialize by calling <code>ctx.objectDefinitionSource.initialize(
	 * 	ctx.authenticateService.securityConfig.security.annotationStaticRules,
	 * 	ctx.grailsUrlMappingsHolder,
	 * 	ApplicationHolder.application.controllerClasses)</code>
	 *
	 * @param staticRules  keys are URL patterns, values are role names for that pattern
	 * @param urlMappingsHolder  mapping holder
	 * @param controllerClasses  all controllers
	 */
	public void initialize(
			final Map<String, Collection<String>> staticRules,
			final UrlMappingsHolder urlMappingsHolder,
			final GrailsClass[] controllerClasses) {

		Map<String, Map<String, Set<String>>> actionRoleMap = new HashMap<String, Map<String,Set<String>>>();
		Map<String, Set<String>> classRoleMap = new HashMap<String, Set<String>>();

		Assert.notNull(staticRules, "staticRules map is required");
		Assert.notNull(urlMappingsHolder, "urlMappingsHolder is required");

		_compiled.clear();

		_urlMappingsHolder = urlMappingsHolder;

		for (GrailsClass controllerClass : controllerClasses) {
			findControllerAnnotations((GrailsControllerClass)controllerClass, actionRoleMap, classRoleMap);
		}

		compileActionMap(actionRoleMap);
		compileClassMap(classRoleMap);
		compileStaticRules(staticRules);

		if (_log.isTraceEnabled()) {
			_log.trace("configs: " + _compiled);
		}
	}

	private void compileActionMap(final Map<String, Map<String, Set<String>>> map) {
		for (Map.Entry<String, Map<String, Set<String>>> controllerEntry : map.entrySet()) {
			String controllerName = controllerEntry.getKey();
			Map<String, Set<String>> actionRoles = controllerEntry.getValue();
			for (Map.Entry<String, Set<String>> actionEntry : actionRoles.entrySet()) {
				String actionName = actionEntry.getKey();
				Set<String> roles = actionEntry.getValue();
				storeMapping(controllerName, actionName, roles, false);
			}
		}
	}

	private void compileClassMap(final Map<String, Set<String>> classRoleMap) {
		for (Map.Entry<String, Set<String>> entry : classRoleMap.entrySet()) {
			String controllerName = entry.getKey();
			Set<String> roles = entry.getValue();
			storeMapping(controllerName, null, roles, false);
		}
	}

	private void compileStaticRules(final Map<String, Collection<String>> staticRules) {
		for (Map.Entry<String, Collection<String>> entry : staticRules.entrySet()) {
			String pattern = entry.getKey();
			Collection<String> roles = entry.getValue();
			storeMapping(pattern, null, roles, true);
		}
	}

	private void storeMapping(final String controllerNameOrPattern, final String actionName,
			final Collection<String> roles, final boolean isPattern) {

		String fullPattern;
		if (isPattern) {
			fullPattern = controllerNameOrPattern;
		}
		else {
			StringBuilder sb = new StringBuilder();
			sb.append('/').append(controllerNameOrPattern);
			if (actionName != null) {
				sb.append('/').append(actionName);
			}
			sb.append("/**");
			fullPattern = sb.toString();
		}

		ConfigAttributeDefinition configAttribute = new ConfigAttributeDefinition(
				roles.toArray(new String[roles.size()]));

		Object key = _urlMatcher.compile(fullPattern);
		ConfigAttributeDefinition replaced = _compiled.put(key, configAttribute);
		if (replaced != null) {
			_log.warn("replaced rule for '" + key + "' with roles " + replaced.getConfigAttributes()
					+ " with roles " + configAttribute.getConfigAttributes());
		}
	}

	private void findControllerAnnotations(final GrailsControllerClass controllerClass,
			final Map<String, Map<String, Set<String>>> actionRoleMap,
			final Map<String, Set<String>> classRoleMap) {

		Class<?> clazz = controllerClass.getClazz();
		String controllerName = WordUtils.uncapitalize(controllerClass.getName());

		Secured annotation = clazz.getAnnotation(Secured.class);
		if (annotation != null) {
			classRoleMap.put(controllerName, asSet(annotation.value()));
		}

		Map<String, Set<String>> annotatedClosureNames = findActionRoles(clazz);
		if (annotatedClosureNames != null) {
			actionRoleMap.put(controllerName, annotatedClosureNames);
		}
	}

	private Map<String, Set<String>> findActionRoles(final Class<?> clazz) {
		// since action closures are defined as "def foo = ..." they're
		// fields, but they end up as private
		Map<String, Set<String>> actionRoles = new HashMap<String, Set<String>>();
		for (Field field : clazz.getDeclaredFields()) {
			Secured annotation = field.getAnnotation(Secured.class);
			if (annotation != null) {
				actionRoles.put(field.getName(), asSet(annotation.value()));
			}
		}
		return actionRoles;
	}

	private Set<String> asSet(final String[] strings) {
		Set<String> set = new HashSet<String>();
		for (String string : strings) {
			set.add(string);
		}
		return set;
	}

	/**
	 * For debugging.
	 * @return  an unmodifiable map of {@link AnnotationFilterInvocationDefinition}ConfigAttributeDefinition
	 * keyed by compiled patterns
	 */
	public Map<Object, ConfigAttributeDefinition> getConfigAttributeMap() {
		return Collections.unmodifiableMap(_compiled);
	}

	/**
	 * {@inheritDoc}
	 * @see org.springframework.beans.factory.InitializingBean#afterPropertiesSet()
	 */
	public void afterPropertiesSet() {
		Assert.notNull(_urlMatcher, "url matcher is required");
	}
}
