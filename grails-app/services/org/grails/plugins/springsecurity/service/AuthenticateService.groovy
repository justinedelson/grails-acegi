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
package org.grails.plugins.springsecurity.service

import org.codehaus.groovy.grails.plugins.springsecurity.AuthorizeTools

import org.springframework.security.context.SecurityContextHolder as SCH
import org.springframework.security.userdetails.UserDetails

/**
 * Authentication utility methods.
 *
 * @author T.Yamamoto
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
class AuthenticateService {

	boolean transactional = false

	private securityConfig

	/** dependency injection for authenticationTrustResolver */
	def authenticationTrustResolver

	/** dependency injection for {@link GrailsFilterInvocationDefinition} */
	def objectDefinitionSource

	/** dependency injection for the password encoder */
	def passwordEncoder

	/**
	 * @deprecated You can invoke tags from controllers (since grails-0.6)
	 */
	boolean ifAllGranted(role) {
		return AuthorizeTools.ifAllGranted(role)
	}

	/**
	 * @deprecated You can invoke tags from controllers (since grails-0.6)
	 */
	boolean ifNotGranted(role) {
		return AuthorizeTools.ifNotGranted(role)
	}

	/**
	 * @deprecated You can invoke tags from controllers (since grails-0.6)
	 */
	boolean ifAnyGranted(role) {
		return AuthorizeTools.ifAnyGranted(role)
	}

	/**
	 * Get the currently logged in user's principal.
	 * @return the principal or <code>null</code> if not logged in
	 */
	def principal() {
		return SCH.context?.authentication?.principal
	}

	/**
	 * Get the currently logged in user's domain class.
	 * @return the domain object or <code>null</code> if not logged in
	 */
	def userDomain() {
		return isLoggedIn() ? principal().domainClass : null
	}

	/**
	 * Load the security configuration.
	 * @return the config
	 */
	ConfigObject getSecurityConfig() {
		if (securityConfig == null) {
			securityConfig = AuthorizeTools.getSecurityConfig()
		}
		return securityConfig
	}

	/**
	 * @deprecated use <code>encodePassword</code> instead
	 */
	String passwordEncoder(String passwd) {
		return encodePassword(passwd)
	}

	/**
	 * Encode the password using the configured PasswordEncoder.
	 */
	String encodePassword(String passwd) {
		return passwordEncoder.encodePassword(passwd, null)
	}

	/**
	 * Check if the request was triggered by an Ajax call.
	 * @param request the request
	 * @return <code>true</code> if Ajax
	 */
	boolean isAjax(request) {
		return AuthorizeTools.isAjax(request)
	}

	/**
	 * Quick check to see if the current user is logged in.
	 * @return <code>true</code> if the authenticated and not anonymous
	 */
	boolean isLoggedIn() {
		def authentication = SCH.context.authentication
		return authentication && !authenticationTrustResolver.isAnonymous(authentication)
	}

	/**
	 * Call when editing, creating, or deleting a Requestmap to flush the cached
	 * configuration and rebuild using the most recent data.
	 */
	void clearCachedRequestmaps() {
		objectDefinitionSource?.reset()
	}

	/**
	 * Delete a role, and if Requestmap class is used to store roles, remove the role
	 * from all Requestmap definitions. If a Requestmap's config attribute is this role,
	 * it will be deleted.
	 *
	 * @param role  the role to delete
	 */
	void deleteRole(role) {
		def conf = getSecurityConfig().security
		String configAttributeName = conf.requestMapConfigAttributeField
		String authorityFieldName = conf.authorityField

		role.getClass().withTransaction { status ->
			if (conf.useRequestMapDomainClass) {
				String roleName = role."$authorityFieldName"
				def requestmaps = findRequestmapsByRole(roleName, role.getClass(), conf)
				requestmaps.each { rm ->
					String configAttribute = rm."$configAttributeName"
					if (configAttribute.equals(roleName)) {
						rm.delete()
					}
					else {
						List parts = configAttribute.split(',') as List
						parts.remove roleName
						rm."$configAttributeName" = parts.join(',')
					}
				}
				clearCachedRequestmaps()
			}

			role.delete()
		}
	}

	/**
	 * Update a role, and if Requestmap class is used to store roles, replace the new role
	 * name in all Requestmap definitions that use it if the name was changed.
	 *
	 * @param role  the role to update
	 * @param newProperties  the new role attributes ('params' from the calling controller)
	 */
	boolean updateRole(role, newProperties) {

		def conf = getSecurityConfig().security

		String configAttributeName = conf.requestMapConfigAttributeField
		String authorityFieldName = conf.authorityField

		String oldRoleName = role."$authorityFieldName"
		role.properties = newProperties

		role.save()
		if (role.hasErrors()) {
			return false
		}

		if (conf.useRequestMapDomainClass) {
			String newRoleName = role."$authorityFieldName"
			if (newRoleName != oldRoleName) {
				def requestmaps = findRequestmapsByRole(oldRoleName, role.getClass(), conf)
				requestmaps.each { rm ->
					rm."$configAttributeName" = rm."$configAttributeName".replace(oldRoleName, newRoleName)
				}
			}
			clearCachedRequestmaps()
		}

		return true
	}

	private List findRequestmapsByRole(String roleName, domainClass, conf) {
		String requestmapClassName = conf.requestMapClass
		String configAttributeName = conf.requestMapConfigAttributeField
		return domainClass.executeQuery(
				"SELECT rm FROM $requestmapClassName rm " +
				"WHERE rm.$configAttributeName LIKE :roleName",
				[roleName: "%$roleName%"])
	}
}
