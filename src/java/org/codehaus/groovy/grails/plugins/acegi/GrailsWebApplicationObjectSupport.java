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
package org.codehaus.groovy.grails.plugins.acegi;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.codehaus.groovy.grails.commons.GrailsApplication;
import org.codehaus.groovy.grails.commons.spring.GrailsWebApplicationContext;
import org.codehaus.groovy.grails.web.servlet.GrailsApplicationAttributes;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.springframework.orm.hibernate3.SessionFactoryUtils;
import org.springframework.orm.hibernate3.SessionHolder;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.web.context.support.WebApplicationObjectSupport;

/**
 * Grails Web Application Object Support
 * @author T.Yamamoto
 */
abstract class GrailsWebApplicationObjectSupport extends WebApplicationObjectSupport {

	private static final Log logger = LogFactory.getLog(GrailsWebApplicationObjectSupport.class);
	protected SessionFactory sessionFactory;
	protected Session session;
	/**
	 * Returns GrailsApplication from context
	 * @return GrailsApplication
	 */
	public GrailsApplication getGrailsApplication(){
		GrailsWebApplicationContext context = 
			(GrailsWebApplicationContext)getServletContext()
			.getAttribute(GrailsApplicationAttributes.APPLICATION_CONTEXT);
		GrailsApplication grailsApplication = 
			(GrailsApplication)context.getBean(GrailsApplication.APPLICATION_ID);
		logger.debug(""+grailsApplication);
		
		return grailsApplication;
	}
	
	/**
	 * set up hibernate session
	 */
	protected void setUpSession() {
		try {
			sessionFactory = (SessionFactory)getWebApplicationContext().getBean("sessionFactory");
			session = SessionFactoryUtils.getSession(sessionFactory, true);
//			session = ((SessionHolder)TransactionSynchronizationManager.getResource(sessionFactory)).getSession();
			
			SessionHolder sessionHolder = new SessionHolder(session);
            if(TransactionSynchronizationManager.hasResource(sessionFactory)) {
                this.session = ((SessionHolder)TransactionSynchronizationManager.getResource(sessionFactory)).getSession();
            }else{
            	TransactionSynchronizationManager.bindResource(sessionFactory, sessionHolder); 
            }
			
		} catch (Exception e) {
			logger.error(e.getMessage());
			e.printStackTrace();
		}
	}
	/**
	 * Release Session
	 */
	protected void releaseSession() {
		  SessionHolder sessionHolder = (SessionHolder) TransactionSynchronizationManager.unbindResource(sessionFactory);
		  SessionFactoryUtils.releaseSession(sessionHolder.getSession(), sessionFactory); 
		  logger.debug("Session released");
	}
	
}
