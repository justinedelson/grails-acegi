package org.codehaus.groovy.grails.plugins.springsecurity.kerberos;

import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.spi.LoginModule;

public class MockLoginModule implements LoginModule {

	public boolean abort() {
		return false;
	}

	public boolean commit() {
		return true;
	}

	public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState,
			Map<String, ?> options) {
		// do nothing
	}

	public boolean login() {
		return true;
	}

	public boolean logout() {
		return true;
	}
}
