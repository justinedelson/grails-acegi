/* Copyright 2006-2007 the original author or authors.
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

import java.security.MessageDigest

import grails.util.GrailsUtil

import org.apache.commons.codec.binary.Hex

import org.codehaus.groovy.grails.plugins.springsecurity.AuthorizeTools

import org.springframework.security.context.SecurityContextHolder as SCH
import org.springframework.security.providers.encoding.MessageDigestPasswordEncoder
import org.springframework.security.ui.AbstractProcessingFilter
import org.springframework.security.userdetails.UserDetails

/**
 * Rewrote to the Groovy from Java source of
 * org.acegisecurity.taglibs.authz.AuthorizeTag
 * for to use from the controllers and a taglib.
 *
 * @author T.Yamamoto
 */
class AuthenticateService {

	boolean transactional = false

	private securityConfig

	/**
	 * @deprecated You can invoke tags from controllers (since grails-0.6)
   	*/
   	def ifAllGranted(role) {
		return AuthorizeTools.ifAllGranted(role)
	}

	/**
   	 * @deprecated You can invoke tags from controllers (since grails-0.6)
   	 */
   	def ifNotGranted(role) {
   		return AuthorizeTools.ifNotGranted(role)
	}

	/**
	 * @deprecated You can invoke tags from controllers (since grails-0.6)
	 */
	def ifAnyGranted(role) {
		return AuthorizeTools.ifAnyGranted(role)
	}

	/**
	 * Get the currently logged in user's principal.
	 * @return  the principal or <code>null</code> if not logged in
	 */
	def principal() {
		return SCH?.context?.authentication?.principal
	}

	/**
	 * Get the currently logged in user's domain class.
	 * @return  the domain object or <code>null</code> if not logged in
	 */
	def userDomain() {
		return isLoggedIn() ? principal().domainClass : null
	}

	/**
	 * Load the security configuration.
	 * @return  the config
	 */
	ConfigObject getSecurityConfig() {
		if (securityConfig == null) {
			securityConfig = AuthorizeTools.getSecurityConfig()
		}
		return securityConfig
	}

	/**
	 * returns a MessageDigest password.
	 * (changes algorithm method dynamically by param of config)
	 * @deprecated  use <code>encodePassword</code> instead
	 */
	def passwordEncoder(String passwd) {
		return encodePassword(passwd)
	}

	def encodePassword(String passwd) {
		def securityConfig = getSecurityConfig()
		def algorithm = securityConfig.algorithm
		def encodeHashAsBase64 = securityConfig.encodeHashAsBase64
		def encoder = new MessageDigestPasswordEncoder(algorithm, encodeHashAsBase64)
		return encoder.encodePassword(passwd, null)
	}

	/**
	 * Check if the request was triggered by an Ajax call.
	 * @param request  the request
	 * @return  <code>true</code> if Ajax
	 */
	boolean isAjax(request) {

		// look for an ajax=true parameter
		if ('true' == request.getParameter('ajax')) {
			return true
		}

		// check the current request's headers
		def ajaxHeader = getSecurityConfig().ajaxHeader
		if (request.getHeader(ajaxHeader) != null) {
			return true
		}

		// check the SavedRequest's headers
		def savedRequest = request.session[AbstractProcessingFilter.SPRING_SECURITY_SAVED_REQUEST_KEY]
		if (savedRequest) {
			return savedRequest.getHeaderValues(ajaxHeader).hasNext()
		}

		return false
	}

	/**
	 * Quick check to see if the current user is logged in.
	 * @return  <code>true</code> if the principal is a <code>UserDetails</code> or subclass
	 */
	boolean isLoggedIn() {
		return principal() instanceof UserDetails
	}
}
