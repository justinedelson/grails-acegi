/*
 * Copyright 2008 the original author or authors.
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
package org.codehaus.groovy.grails.plugins.acegi.gv;

import org.apache.commons.logging.Log
import org.apache.commons.logging.LogFactory
import org.acegisecurity.GrantedAuthority
import org.acegisecurity.GrantedAuthorityImpl
import org.acegisecurity.userdetails.UserDetails
import org.acegisecurity.userdetails.UserDetailsService
import org.acegisecurity.userdetails.UsernameNotFoundException
import org.springframework.dao.DataAccessException

/**
 * UserDetailsService with
 * GrailsDomainClass Data Access Object
 * @author Tsuyoshi Yamamoto
 * @since 2008/02/08 18:04:51
 */
public class GrailsDaoImpl extends SessionSupport implements UserDetailsService {

  private static final Log logger = LogFactory.getLog(GrailsDaoImpl.class)
  
  /** Hibernate session factory */
  def sessionFactory
  /** LoginUser Domain Class */
  def loginUserDomainClass
  /** username field name */
  def userName
  /** password field name */
  def password
  /** enabled field name */
  def enabled
  /** LoginUser getAuthorities field */
  def relationalAuthorities
  /** authority field name */
  def authority
  /** for customise authorities */
  def authoritiesMethod
  
  /**
   * Load login user by Username
   */
  public UserDetails loadUserByUsername(String arg0) throws UsernameNotFoundException, DataAccessException {
    setUpSession()
    def grailsUser
    //def hsession = sessionFactory.openSession()//.getCurrentSession()
    def query = session.createQuery("from $loginUserDomainClass where $userName=:userName")
    query.setProperties([userName:arg0])
    def list = query/*.setCacheable(true)*/.list()
    
    
    if(list.size()>0){
      def user = list[0]
      def _authorities=[]
      if(relationalAuthorities!=null){
        def authorities = user."$relationalAuthorities"
        if ( authorities==null || (authorities!=null && authorities.size() == 0) ) {
          logger.error("User [$arg0] has no GrantedAuthority")
          throw new UsernameNotFoundException("User has no GrantedAuthority ")
        }
        
        authorities.each{a->
          _authorities << new GrantedAuthorityImpl(a."$authority")
        }
        
      }else if(relationalAuthorities==null && authoritiesMethod!=null){
        def roles = user."$authoritiesMethod"()
        if ( roles==null || (roles!=null && roles.size() == 0) ) {
          logger.error("User [$arg0] has no GrantedAuthority")
          throw new UsernameNotFoundException("User has no GrantedAuthority")
        }
        roles.each{role->
          _authorities << new GrantedAuthorityImpl(role)
        }
      }else{
        logger.error("User [$arg0] has no GrantedAuthority")
        throw new UsernameNotFoundException("User has no GrantedAuthority")
      }
      
      //set properties to GrailsUser extends org.acegisecurity.userdetails.User
      grailsUser = new GrailsUser(
        user."$userName", user."$password", user."$enabled" , true, true, true, _authorities as GrantedAuthorityImpl[])
      //and set LoginUser domain class object
      grailsUser.setDomainClass(user)

    }else{
      logger.error("User not found: " + arg0)
      throw new UsernameNotFoundException("User not found.",arg0)
    }
    
    releaseSession()
    return grailsUser
  }
  
}
