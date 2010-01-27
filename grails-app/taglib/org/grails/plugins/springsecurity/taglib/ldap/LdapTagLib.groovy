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
package org.grails.plugins.springsecurity.taglib.ldap

import org.codehaus.groovy.grails.plugins.springsecurity.ldap.LdapUtils

/**
 * LDAP tags.
 *
 * @author Ben McGuire
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
class LdapTagLib {

	def authenticateService

	/**
	 * <g:ldapAttribute name="cn" />
	 */
	def ldapAttribute = { attrs ->
		if (authenticateService.isLoggedIn()) {
			out << LdapUtils.getAttribute(attrs.name)
		}
	}

	/**
	 * <g:ldapAttributes name="objectClass" />
	 */
	def ldapAttributes = { attrs ->
		if (authenticateService.isLoggedIn()) {
			out << LdapUtils.getAttributes(attrs.name)?.join(',')
		}
	}
}
