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
package org.codehaus.groovy.grails.plugins.springsecurity

import jcifs.smb.NtlmPasswordAuthentication

import org.springframework.security.BadCredentialsException
import org.springframework.security.GrantedAuthority
import org.springframework.security.GrantedAuthorityImpl
import org.springframework.security.providers.UsernamePasswordAuthenticationToken
import org.springframework.security.ui.ntlm.NtlmUsernamePasswordAuthenticationToken
import org.springframework.util.ReflectionUtils

/**
 * Unit tests for GrailsAuthenticationProcessingFilter.
 *
 * @author <a href='mailto:beckwithb@studentsonly.com'>Burt Beckwith</a>
 */
class GrailsDaoAuthenticationProviderTests extends AbstractSecurityTest {

	private _provider = new GrailsDaoAuthenticationProvider()

	void testAdditionalAuthenticationChecks() {

		GrantedAuthority[] authorities = [new GrantedAuthorityImpl('ROLE_ADMIN')]
		def user = new GrailsUserImpl('username', 'password', true, true, true, true,
				authorities, null)
		def field = ReflectionUtils.findField(user.class, 'password')
		field.accessible = true
		field.set(user, null) // can't set null in constructor

		_provider.additionalAuthenticationChecks user,
				new NtlmUsernamePasswordAuthenticationToken(new NtlmPasswordAuthentication("foo"), true)

		shouldFail(BadCredentialsException) {
			_provider.additionalAuthenticationChecks user,
				new UsernamePasswordAuthenticationToken('username', 'password', authorities)
		}
	}
}
