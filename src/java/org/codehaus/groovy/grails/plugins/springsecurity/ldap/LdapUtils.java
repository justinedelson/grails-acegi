/* Copyright 2006-2010 the original author or authors.
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
package org.codehaus.groovy.grails.plugins.springsecurity.ldap;

import java.util.ArrayList;
import java.util.List;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;

import org.apache.log4j.Logger;
import org.springframework.security.context.SecurityContextHolder;

/**
 * LDAP utility methods.
 *
 * @author Ben McGuire
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
public class LdapUtils {

	private static final Logger LOG = Logger.getLogger(LdapUtils.class);

	private LdapUtils() {
		// static only
	}

	/**
	 * Retrieves the LDAP attribute value for the specified name.
	 * @param attributeName the LDAP attribute name
	 * @return the value or <code>null</code> if not available
	 */
	public static String getAttribute(String attributeName) {
		Object currentUser = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
		if (!(currentUser instanceof GrailsLdapUser)) {
			LOG.warn("Must be using an implementation of " + GrailsLdapUser.class.getName() + " to retrieve Attributes");
			return null;
		}

		try {
			return ((GrailsLdapUser)currentUser).getAttributes().get(attributeName).get(0).toString();
		}
		catch (NamingException e) {
			LOG.warn("Unable to retrieve attribute " + attributeName + " from the currently logged in user", e);
			return null;
		}
		catch (RuntimeException e) {
			LOG.warn("Unable to retrieve attribute " + attributeName + " from the currently logged in user", e);
			return null;
		}
	}

	/**
	 * Retrieves the LDAP attribute values for the specified name.
	 * @param attributeName the LDAP attribute name
	 * @return  the values or <code>null</code> if not available
	 */
	public static List<String> getAttributes(String attributeName) {
		Object currentUser = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
		if (!(currentUser instanceof GrailsLdapUser)) {
			LOG.warn("Must be using an implementation of " + GrailsLdapUser.class.getName() + " to retrieve Attributes");
			return null;
		}

		List<String> values = new ArrayList<String>();
		NamingEnumeration<?> attributes = null;
		try {
			attributes = ((GrailsLdapUser)currentUser).getAttributes().get(attributeName).getAll();
			if (attributes != null) {
				while (attributes.hasMore()) {
					values.add(attributes.next().toString());
				}
			}
		}
		catch (NamingException e) {
			LOG.warn("Unable to retrieve attribute " + attributeName + " from the currently logged in user", e);
		}
		catch (RuntimeException e) {
			LOG.warn("Unable to retrieve attribute " + attributeName + " from the currently logged in user", e);
		}

		return values;
	}
}
