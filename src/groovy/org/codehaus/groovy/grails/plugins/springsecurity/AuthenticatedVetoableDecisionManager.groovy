package org.codehaus.groovy.grails.plugins.springsecurity

import org.springframework.security.AccessDeniedException
import org.springframework.security.Authentication
import org.springframework.security.ConfigAttribute
import org.springframework.security.ConfigAttributeDefinition
import org.springframework.security.vote.AbstractAccessDecisionManagerimport org.springframework.security.vote.AccessDecisionVoterimport org.springframework.security.vote.AuthenticatedVoter

/**
 * Uses the affirmative-based logic for roles, i.e. any in the list will grant access, but allows
 * an authenticated voter to 'veto' access. This allows specification of roles and
 * IS_AUTHENTICATED_FULLY on one line in SecurityConfig.groovy.
 *
 * @author <a href='mailto:beckwithb@studentsonly.com'>Burt Beckwith</a>
 */
class AuthenticatedVetoableDecisionManager extends AbstractAccessDecisionManager {

	/**
	 * {@inheritDoc}
	 * @see org.springframework.security.vote.AbstractAccessDecisionManager#decide(
	 * 	org.springframework.security.Authentication, java.lang.Object,
	 * 	org.springframework.security.ConfigAttributeDefinition)
	 */
	void decide(Authentication authentication, Object object, ConfigAttributeDefinition config)
            throws AccessDeniedException {

		boolean authenticatedVotersGranted = checkAuthenticatedVoters(authentication, object, config)
		boolean otherVotersGranted = checkOtherVoters(authentication, object, config)

		if (!authenticatedVotersGranted && !otherVotersGranted) {
			checkAllowIfAllAbstainDecisions()
		}
	}

	/**
	 * Allow any <code>AuthenticatedVoter</code> to veto. If any voter denies,
	 * throw an exception; if any grant, return <code>true</code>;
	 * otherwise return <code>false</code> if all abstain.
	 */
	private boolean checkAuthenticatedVoters(authentication, object, config) {
		boolean grant = false
		for (AccessDecisionVoter voter in decisionVoters) {
			if (voter instanceof AuthenticatedVoter) {
				int result = voter.vote(authentication, object, config)
				switch (result) {
					case AccessDecisionVoter.ACCESS_GRANTED:
						grant = true
						break
					case AccessDecisionVoter.ACCESS_DENIED:
						deny()
						break
					default: // abstain
						break
				}
			}
		}
		return grant
	}

	/**
	 * Check the other (non-<code>AuthenticatedVoter</code>) voters. If any voter grants,
	 * return true. If any voter denies, throw exception. Otherwise return false to indicate
	 * that all abstained.
	 */
	private boolean checkOtherVoters(authentication, object, config) {
		int deny = 0
		for (AccessDecisionVoter voter in decisionVoters) {
			if (voter instanceof AuthenticatedVoter) {
				continue
			}

			int result = voter.vote(authentication, object, config)
			switch (result) {
            	case AccessDecisionVoter.ACCESS_GRANTED:
            		return true
            	case AccessDecisionVoter.ACCESS_DENIED:
            		deny++
            		break
				default: // abstain
            		break
            }
        }

        if (deny) {
            deny()
        }

        // all abstain
        return false
	}

	private void deny() {
		throw new AccessDeniedException(messages.getMessage(
				"AbstractAccessDecisionManager.accessDenied",
				"Access is denied"))
	}
}
