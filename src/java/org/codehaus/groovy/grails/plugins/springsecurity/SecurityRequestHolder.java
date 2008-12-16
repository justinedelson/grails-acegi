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

import javax.servlet.http.HttpServletRequest;

/**
 * Uses a <code>ThreadLocal</code> to store the current request.
 *
 * @author <a href='mailto:beckwithb@studentsonly.com'>Burt Beckwith</a>
 */
public final class SecurityRequestHolder {

	private static final ThreadLocal<HttpServletRequest> HOLDER = new ThreadLocal<HttpServletRequest>();

	private SecurityRequestHolder() {
		// static only
	}

	/**
	 * Clear the saved request.
	 */
	public static void reset() {
		HOLDER.set(null);
	}

	/**
	 * Set the current request.
	 * @param request  the request
	 */
	public static void setRequest(final HttpServletRequest request) {
		HOLDER.set(request);
	}

	/**
	 * Get the current request.
	 * @return  the request
	 */
	public static HttpServletRequest getRequest() {
		return HOLDER.get();
	}
}
