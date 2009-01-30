/**
 * Copyright 2006-2009 the original author or authors.
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
import java.util.Collection;
import java.util.List;
import java.util.Set;

import org.apache.log4j.Logger;
import org.codehaus.groovy.grails.commons.ApplicationHolder;
import org.codehaus.groovy.grails.commons.GrailsDomainClass;
import org.hibernate.Session;
import org.springframework.beans.BeanWrapper;
import org.springframework.beans.BeanWrapperImpl;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.dao.DataAccessException;
import org.springframework.security.GrantedAuthority;
import org.springframework.security.GrantedAuthorityImpl;
import org.springframework.security.userdetails.UserDetails;
import org.springframework.security.userdetails.UserDetailsService;
import org.springframework.security.userdetails.UsernameNotFoundException;
import org.springframework.util.StringUtils;

/**
 * {@link UserDetailsService} with {@link GrailsDomainClass} Data Access Object.
 * @author Tsuyoshi Yamamoto
 * @author <a href='mailto:beckwithb@studentsonly.com'>Burt Beckwith</a>
 */
public class GrailsDaoImpl
       extends GrailsWebApplicationObjectSupport
       implements UserDetailsService, InitializingBean {

	private final Logger logger = Logger.getLogger(getClass());

	private String _loginUserDomainClassName;
	private String _usernameFieldName;
	private String _passwordFieldName;
	private String _enabledFieldName;
	private String _relationalAuthoritiesFieldName;
	private String _authoritiesMethodName;

	private String _roleDomainClassName;
	private String _authorityFieldName;

	private Method _getPassword;
	private Method _getEnabled;
	private Method _getAuthoritiesMethod;
	private Method _getAuthoritiesGetterMethod;
	private Method _getAuthority;

	private boolean _useNtlm;

	/**
	 * {@inheritDoc}
	 * @see org.springframework.security.userdetails.UserDetailsService#loadUserByUsername(java.lang.String)
	 */
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException, DataAccessException {
		return loadUserByUsername(username, true);
	}

	/**
	 * Load a user by username, optionally not loading roles.
	 * @param username  the login name
	 * @param loadRoles  if <code>true</code> load roles from the database
	 * @return the user if found, otherwise throws {@link UsernameNotFoundException}
	 * @throws UsernameNotFoundException  if the user isn't found
	 * @throws DataAccessException  if there's a database problem
	 */
	public UserDetails loadUserByUsername(String username, final boolean loadRoles)
			throws UsernameNotFoundException, DataAccessException {

		if (_useNtlm) {
			username = username.toLowerCase();
		}

		GrailsWebApplicationObjectSupport.SessionContainer container = setUpSession();
		try {
			Object user = loadDomainUser(username, container.getSession());
			GrantedAuthority[] authorities = loadAuthorities(user, username, loadRoles);
			String password = getPassword(user);
			boolean enabled = getEnabled(user);
			return createUserDetails(username, password, enabled, authorities, user);
		}
		finally {
			releaseSession(container);
		}
	}

	protected GrantedAuthority[] loadAuthorities(final Object user, final String username, final boolean loadRoles) {
		if (!loadRoles) {
			return new GrantedAuthorityImpl[0];
		}

		if (StringUtils.hasLength(_relationalAuthoritiesFieldName)) {
			return createRolesByRelationalAuthorities(user, username);
		}

		if (StringUtils.hasLength(_authoritiesMethodName)) {
			return createRolesByAuthoritiesMethod(user, username);
		}

		logger.error("User [" + username + "] has no GrantedAuthority");
		throw new UsernameNotFoundException("User has no GrantedAuthority");
	}

	protected Object loadDomainUser(final String username, final Session session)
			throws UsernameNotFoundException, DataAccessException {

		List<?> users = session.createQuery(
				"FROM " + _loginUserDomainClassName + " WHERE " + _usernameFieldName + "=:username")
				.setString("username", username)
				.setCacheable(true)
				.list();

		if (users.isEmpty()) {
			logger.error("User not found: " + username);
			throw new UsernameNotFoundException("User not found", username);
		}

		return users.get(0);
	}

	/**
	 * Create the {@link UserDetails} instance. Subclasses can override to inherit core functionality
	 * but determine the concrete class without reimplementing the entire class.
	 * @param username the username
	 * @param password the password
	 * @param enabled set to <code>true</code> if the user is enabled
	 * @param authorities the authorities that should be granted to the caller
	 * @param user  the user domain instance
	 * @return  the instance
	 */
	protected UserDetails createUserDetails(
			String username, String password, boolean enabled,
			GrantedAuthority[] authorities, Object user) {

		return new GrailsUserImpl(username, password, enabled, true, true, true, authorities, user);
	}

	protected GrantedAuthority[] createRolesByAuthoritiesMethod(final Object user, final String username) {
		Set<String> authorityStrings = getAuthorityNames(user);
		assertNotEmpty(authorityStrings, username);

		List<GrantedAuthorityImpl> authorities = new ArrayList<GrantedAuthorityImpl>();
		for (String roleName : authorityStrings) {
			authorities.add(new GrantedAuthorityImpl(roleName));
		}

		return authorities.toArray(new GrantedAuthorityImpl[authorities.size()]);
	}

	protected GrantedAuthority[] createRolesByRelationalAuthorities(final Object user, final String username) {
		// get authorities from User [User]--M:M--[Authority]

		Set<?> userAuthorities = getAuthoritiesByProperty(user);
		assertNotEmpty(userAuthorities, username);

		List<GrantedAuthorityImpl> authorities = new ArrayList<GrantedAuthorityImpl>();
		for (Object role : userAuthorities) {
			String roleName = getAuthority(role);
			authorities.add(new GrantedAuthorityImpl(roleName));
		}

		return authorities.toArray(new GrantedAuthorityImpl[authorities.size()]);
	}

	protected void assertNotEmpty(final Collection<?> authorities, final String username) {
		if (authorities == null || authorities.isEmpty()) {
			logger.error("User [" + username + "] has no GrantedAuthority");
			throw new UsernameNotFoundException("User has no GrantedAuthority");
		}
	}

	protected Logger getLog() {
		return logger;
	}

	protected Object invoke(final Method method, final Object o) {
		try {
			return method.invoke(o);
		}
		catch (IllegalAccessException e) {
			throw handleReflectionException(e);
		}
		catch (InvocationTargetException e) {
			throw handleReflectionException(e);
		}
	}

	protected RuntimeException handleReflectionException(final Exception e) {
		return new RuntimeException(e);
	}

	/**
	 * {@inheritDoc}
	 * @see org.springframework.beans.factory.InitializingBean#afterPropertiesSet()
	 */
	public void afterPropertiesSet() throws SecurityException, NoSuchMethodException {

		if (StringUtils.hasLength(_relationalAuthoritiesFieldName) &&
				StringUtils.hasLength(_authoritiesMethodName)) {
			throw new IllegalArgumentException(
					"Only one of 'relationalAuthoritiesField' or 'authoritiesMethodName' can be specified");
		}

		findMethods();
	}

	private void findMethods() throws SecurityException, NoSuchMethodException {
		BeanWrapper userClassWrapper = null;
		if (StringUtils.hasLength(_loginUserDomainClassName)) {
			Class<?> userClass = ApplicationHolder.getApplication().getClassForName(_loginUserDomainClassName);
			userClassWrapper = new BeanWrapperImpl(userClass);
			_getPassword = userClassWrapper.getPropertyDescriptor(_passwordFieldName).getReadMethod();
			_getEnabled = userClassWrapper.getPropertyDescriptor(_enabledFieldName).getReadMethod();
		}

		Class<?> roleClass = null;
		BeanWrapper roleClassWrapper = null;
		if (StringUtils.hasLength(_roleDomainClassName)) {
			roleClass = ApplicationHolder.getApplication().getClassForName(_roleDomainClassName);
			roleClassWrapper = new BeanWrapperImpl(roleClass);
		}

		if (StringUtils.hasLength(_relationalAuthoritiesFieldName)) {
			if (userClassWrapper != null) {
				_getAuthoritiesGetterMethod = userClassWrapper.getPropertyDescriptor(_relationalAuthoritiesFieldName).getReadMethod();
			}
			if (roleClassWrapper != null) {
				_getAuthority = roleClassWrapper.getPropertyDescriptor(_authorityFieldName).getReadMethod();
			}
		}
		else if (roleClass != null && StringUtils.hasLength(_authoritiesMethodName)) {
			_getAuthoritiesMethod = roleClass.getDeclaredMethod(_authoritiesMethodName);
		}
	}

	protected String getPassword(final Object user) {
		return (String)invoke(_getPassword, user);
	}

	protected boolean getEnabled(final Object user) {
		return (Boolean)invoke(_getEnabled, user);
	}

	@SuppressWarnings("unchecked")
	protected Set<String> getAuthorityNames(final Object user) {
		return (Set<String>)invoke(_getAuthoritiesMethod, user);
	}

	protected Set<?> getAuthoritiesByProperty(final Object user) {
		return (Set<?>)invoke(_getAuthoritiesGetterMethod, user);
	}

	protected String getAuthority(final Object role) {
		return (String)invoke(_getAuthority, role);
	}

	/**
	 * Dependency injection for the User domain class name.
	 * @param name  the name
	 */
	public void setLoginUserDomainClass(final String name) {
		_loginUserDomainClassName = name;
	}

	/**
	 * Dependency injection for the User domain class name.
	 * @param name  the name
	 */
	public void setUsernameFieldName(final String name) {
		_usernameFieldName = name;
	}

	/**
	 * Dependency injection for the User domain class password field name.
	 * @param name  the name
	 */
	public void setPasswordFieldName(final String name) {
		_passwordFieldName = name;
	}

	/**
	 * Dependency injection for the User domain class enabled field name.
	 * @param name  the name
	 */
	public void setEnabledFieldName(final String name) {
		_enabledFieldName = name;
	}

	/**
	 * Dependency injection for the User domain class 'authorities' field name.
	 * @param name  the name
	 */
	public void setRelationalAuthoritiesField(final String name) {
		_relationalAuthoritiesFieldName = name;
	}

	/**
	 * Dependency injection for the User domain class 'getAuthorities()' method name.
	 * @param name  the name
	 */
	public void setAuthoritiesMethodName(final String name) {
		_authoritiesMethodName = name;
	}

	/**
	 * Dependency injection for the Role domain class name.
	 * @param name  the name
	 */
	public void setRoleDomainClass(final String name) {
		_roleDomainClassName = name;
	}

	/**
	 * Dependency injection for the Role domain class 'authority' name.
	 * @param name  the name
	 */
	public void setAuthorityFieldName(final String name) {
		_authorityFieldName = name;
	}

	/**
	 * Dependency injection for whether NTLM is being used.
	 * @param use  <code>true</code> if using NTLM
	 */
	public void setUseNtlm(final boolean use) {
		_useNtlm = use;
	}
}
