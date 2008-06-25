package org.codehaus.groovy.grails.plugins.springsecurity;

import javax.servlet.http.HttpServletRequest;

/**
 * Uses a <code>ThreadLocal</code> to store the current request.
 *
 * @author Burt
 */
public class SecurityRequestHolder {

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
