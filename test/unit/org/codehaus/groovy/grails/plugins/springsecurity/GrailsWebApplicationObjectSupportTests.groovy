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

import org.easymock.EasyMock
import org.hibernate.SessionFactory
import org.hibernate.classic.Session
import org.springframework.orm.hibernate3.SessionHolder
import org.springframework.transaction.support.TransactionSynchronizationManager
import org.springframework.web.context.WebApplicationContext

/**
 * Unit tests for GrailsWebApplicationObjectSupport.
 *
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
class GrailsWebApplicationObjectSupportTests extends GroovyTestCase {

	private _thing = new Thing()

	/**
	 * Test setUpSession() when there's one existing already.
	 */
	void testSetUpSessionExisting() {

		WebApplicationContext context = EasyMock.createMock(WebApplicationContext)
		EasyMock.expect(context.getServletContext()).andReturn(null)

		SessionFactory sessionFactory = EasyMock.createMock(SessionFactory)
		EasyMock.expect(context.getBean('sessionFactory')).andReturn(sessionFactory)

		Session session = EasyMock.createMock(Session)

		EasyMock.replay(context, sessionFactory, session)

		_thing.setApplicationContext(context)

		TransactionSynchronizationManager.bindResource(sessionFactory, new SessionHolder(session))

		GrailsWebApplicationObjectSupport.SessionContainer container = _thing.setUpSession()
		assertEquals session, container.session
		assertTrue container._existingSession

		EasyMock.verify(context, sessionFactory, session)
	}

	/**
	 * Test setUpSession() when there's not one existing already.
	 */
	void testSetUpSessionNew() {

		WebApplicationContext context = EasyMock.createMock(WebApplicationContext)
		EasyMock.expect(context.getServletContext()).andReturn(null)

		SessionFactory sessionFactory = EasyMock.createMock(SessionFactory)
		EasyMock.expect(context.getBean('sessionFactory')).andReturn(sessionFactory)

		Session session = EasyMock.createMock(Session)
		EasyMock.expect(sessionFactory.openSession()).andReturn(session)
		EasyMock.expect(session.getSessionFactory()).andReturn(sessionFactory)

		EasyMock.replay(context, sessionFactory, session)

		_thing.setApplicationContext(context)

		assertFalse TransactionSynchronizationManager.hasResource(sessionFactory)

		GrailsWebApplicationObjectSupport.SessionContainer container = _thing.setUpSession()
		assertEquals session, container.session
		assertFalse container._existingSession

		assertTrue TransactionSynchronizationManager.hasResource(sessionFactory)

		EasyMock.verify(context, sessionFactory, session)
	}

	void testReleaseSession() {
		def session = EasyMock.createMock(Session)
		def sessionFactory = EasyMock.createMock(SessionFactory)

		_thing.sessionFactory = sessionFactory

		EasyMock.replay session, sessionFactory
		def container = new GrailsWebApplicationObjectSupport.SessionContainer(session, false)

		TransactionSynchronizationManager.bindResource(sessionFactory, new SessionHolder(session))

		_thing.releaseSession container

		EasyMock.verify session, sessionFactory
	}
}

class Thing extends GrailsWebApplicationObjectSupport {
	// concrete class to allow access to non-abstract methods
}
