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

import grails.util.GrailsUtil;
import groovy.lang.GroovyClassLoader;
import groovy.util.ConfigObject;
import groovy.util.ConfigSlurper;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.springframework.security.Authentication;
import org.springframework.security.GrantedAuthority;
import org.springframework.security.GrantedAuthorityImpl;
import org.springframework.security.context.SecurityContextHolder;
import org.springframework.util.StringUtils;

/**
 * Helper methods.
 * @author Tsuyoshi Yamamoto
 * @author <a href='mailto:beckwithb@studentsonly.com'>Burt Beckwith</a>
 */
public final class AuthorizeTools {

	private AuthorizeTools() {
		// static only
	}

	private static final Map<Class<?>, Method> CACHED_METHODS = new HashMap<Class<?>, Method>();

	/**
	 * Extract the role names from authorities.
	 * @param  authorities  the authorities (a collection or array of {@link AuthorizeTools}).
	 * @return  the names
	 */
	public static Set<String> authoritiesToRoles(final Object authorities) {
		Set<String> roles = new HashSet<String>();
		for (Object authority : asList(authorities)) {
			String authorityName = extractAuthority(authority);
			if (null == authorityName) {
				throw new IllegalArgumentException(
						"Cannot process GrantedAuthority objects which return null from getAuthority() - attempting to process "
						+ authority);
			}
			roles.add(authorityName);
		}

		return roles;
	}

	/**
	 * Get the current user's authorities.
	 * @return  a list of authorities (empty if not authenticated).
	 */
	public static List<GrantedAuthority> getPrincipalAuthorities() {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		if (null == authentication) {
			return Collections.emptyList();
		}

		GrantedAuthority[] authorities = authentication.getAuthorities();
		if (authorities == null || authorities.length == 0) {
			return Collections.emptyList();
		}

		return Arrays.asList(authorities);
	}

	/**
	 * Split the role names and create {@link GrantedAuthority}s for each.
	 * @param authorizationsString  comma-delimited role names
	 * @return authorities (possibly empty)
	 */
	public static Set<GrantedAuthority> parseAuthoritiesString(final String authorizationsString) {
		Set<GrantedAuthority> requiredAuthorities = new HashSet<GrantedAuthority>();
		for (String auth : StringUtils.commaDelimitedListToStringArray(authorizationsString)) {
			auth = auth.trim();
			if (auth.length() > 0) {
				requiredAuthorities.add(new GrantedAuthorityImpl(auth));
			}
		}

		return requiredAuthorities;
	}

	/**
	 * Find authorities in <code>granted</code> that are also in <code>required</code>.
	 * @param granted  the granted authorities (a collection or array of {@link AuthorizeTools}).
	 * @param required  the required authorities (a collection or array of {@link AuthorizeTools}).
	 * @return  the authority names
	 */
	public static Set<String> retainAll(final Object granted, final Object required) {
		Set<String> grantedRoles = authoritiesToRoles(granted);
		Set<String> requiredRoles = authoritiesToRoles(required);
		grantedRoles.retainAll(requiredRoles);
		return grantedRoles;
	}

	/**
	 * Check if the current user has all of the specified roles.
	 * @param roles  a comma-delimited list of role names
	 * @return  <code>true</code> if the user is authenticated and has all the roles
	 */
	public static boolean ifAllGranted(final String roles) {
		List<GrantedAuthority> granted = getPrincipalAuthorities();
		return granted.containsAll(parseAuthoritiesString(roles));
	}

	/**
	 * Check if the current user has none of the specified roles.
	 * @param roles  a comma-delimited list of role names
	 * @return  <code>true</code> if the user is authenticated and has none the roles
	 */
	public static boolean ifNotGranted(final String roles) {
		List<GrantedAuthority> granted = getPrincipalAuthorities();
		Set<String> grantedCopy = retainAll(granted, parseAuthoritiesString(roles));
		return grantedCopy.isEmpty();
	}

	/**
	 * Check if the current user has any of the specified roles.
	 * @param roles  a comma-delimited list of role names
	 * @return  <code>true</code> if the user is authenticated and has any the roles
	 */
	public static boolean ifAnyGranted(final String roles) {
		List<GrantedAuthority> granted = getPrincipalAuthorities();
		Set<String> grantedCopy = retainAll(granted, parseAuthoritiesString(roles));
		return !grantedCopy.isEmpty();
	}

	/**
	 * Parse and load the security configuration.
	 * @return  the configuration
	 * @throws ClassNotFoundException  if DefaultSecurityConfig.groovy isn't found
	 */
	@SuppressWarnings("unchecked")
	public static ConfigObject getSecurityConfig() throws ClassNotFoundException {

		GroovyClassLoader classLoader = new GroovyClassLoader(AuthorizeTools.class.getClassLoader());

		ConfigSlurper slurper = new ConfigSlurper(GrailsUtil.getEnvironment());
		ConfigObject userConfig = null;
		try {
			userConfig = slurper.parse(classLoader.loadClass("SecurityConfig"));
		}
		catch (Exception e) {
			// ignored, use defaults
		}

		ConfigObject config;
		ConfigObject defaultConfig = slurper.parse(classLoader.loadClass("DefaultSecurityConfig"));
		if (userConfig != null) {
			config = new ConfigObject();
			config.putAll(defaultConfig.merge(userConfig));
		}
		else {
			config = defaultConfig;
		}

		return config;
	}

	private static String extractAuthority(final Object authority) {
		try {
			return (String)findMethod(authority.getClass()).invoke(authority);
		}
		catch (IllegalArgumentException e) {
			throw new RuntimeException(e);
		}
		catch (SecurityException e) {
			throw new RuntimeException(e);
		}
		catch (IllegalAccessException e) {
			throw new RuntimeException(e);
		}
		catch (InvocationTargetException e) {
			throw new RuntimeException(e);
		}
		catch (NoSuchMethodException e) {
			throw new RuntimeException(e);
		}
	}

	private static synchronized Method findMethod(final Class<?> clazz) throws SecurityException, NoSuchMethodException {
		Method method = CACHED_METHODS.get(clazz);
		if (method == null) {
			method = clazz.getDeclaredMethod("getAuthority");
			CACHED_METHODS.put(clazz, method);
		}
		return method;
	}

	private static Collection<?> asList(final Object authorities) {
		if (authorities == null) {
			return Collections.emptyList();
		}

		if (authorities instanceof Collection) {
			return (Collection<?>)authorities;
		}

		if (authorities.getClass().isArray()) {
			return Arrays.asList(authorities);
		}

		// ???
		return Collections.emptyList();
	}
}
