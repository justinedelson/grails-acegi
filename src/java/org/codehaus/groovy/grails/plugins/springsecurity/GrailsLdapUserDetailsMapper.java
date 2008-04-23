package org.codehaus.groovy.grails.plugins.springsecurity;

import groovy.lang.GroovyObject;

import org.springframework.beans.factory.annotation.Required;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.security.GrantedAuthority;
import org.springframework.security.userdetails.UserDetails;
import org.springframework.security.userdetails.ldap.LdapUserDetails;
import org.springframework.security.userdetails.ldap.LdapUserDetailsMapper;

/**
 * Extends the default to return a <code>GrailsLdapUser</code> implementing
 * both <code>GrailsUser</code> and <code>LdapUserDetails</code>.
 *
 * @author <a href='mailto:beckwithb@studentsonly.com'>Burt Beckwith</a>
 */
public class GrailsLdapUserDetailsMapper extends LdapUserDetailsMapper {

	private GrailsDaoImpl _grailsDao;

	/**
	 * {@inheritDoc}
	 * @see org.springframework.security.userdetails.ldap.LdapUserDetailsMapper#mapUserFromContext(
	 * 	org.springframework.ldap.core.DirContextOperations, java.lang.String,
	 * 	org.springframework.security.GrantedAuthority[])
	 */
	@Override
	public UserDetails mapUserFromContext(
			final DirContextOperations ctx, final String username, final GrantedAuthority[] authorities) {
		LdapUserDetails details = (LdapUserDetails)super.mapUserFromContext(ctx, username, authorities);
		GroovyObject domainUser = (GroovyObject)_grailsDao.loadDomainUser(username);
		return new GrailsLdapUser(details, domainUser);
	}

	/**
	 * Dependency injection for <code>GrailsDaoImpl</code>.
	 * @param grailsDao  the dao
	 */
	@Required
	public void setGrailsDao(final GrailsDaoImpl grailsDao) {
		_grailsDao = grailsDao;
	}
}
