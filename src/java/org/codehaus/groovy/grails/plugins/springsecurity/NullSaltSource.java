package org.codehaus.groovy.grails.plugins.springsecurity;

import org.springframework.security.providers.dao.SaltSource;
import org.springframework.security.userdetails.UserDetails;

/**
 * Dummy salt source that's used as the default salt source in the Spring config. Allows
 * users to easily replace in resources.groovy.
 *
 * @author <a href='mailto:beckwithb@studentsonly.com'>Burt Beckwith</a>
 */
public class NullSaltSource implements SaltSource {

	/**
	 * {@inheritDoc}
	 * @see org.springframework.security.providers.dao.SaltSource#getSalt(
	 * 	org.springframework.security.userdetails.UserDetails)
	 */
	public Object getSalt(final UserDetails user) {
		return null;
	}
}
