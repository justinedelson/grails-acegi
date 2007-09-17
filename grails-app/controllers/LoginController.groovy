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

/**
 * Login Controller
 * 
 * @author T.Yamamoto
 */
class LoginController extends AuthBase {
	def description ="login controller"
	def viewOnList="ROLE_SUPERVISOR"
	
	def index = {
		if(logon){
			//if already logon
			redirect(uri:"/")
		}else{
			redirect(action:auth,params:params)
		}
	}

	/**
	 * Login Page
	 */
	def auth = {
		if(logon){
			//if already logon
			redirect(uri:"/")
		}
	}

	/**
	 * Deny
	 */
	def denied ={
		redirect(uri:"/")
	}

	/**
	 * login failed
	 */
	def authfail = {
		flash.message = "login failed"
		redirect(action:auth,params:params)
	}


	/**
	 * load request map
	 */
	def requestMap(hql) {
		Requestmap.findAll(hql)
	}


	/** for authentication with Acegi */
	def loadMessage="[using default Acegi Plugin Configurations]"

	/** Login Controller  /login/ */
	def loginControllerName="LoginController"
	def loginControllerRequestMapMethod="requestMap"

	/** Requestmap domain class */
	def requestMapClass="Requestmap"
	def requestMapPathField="url"
	def requestMapConfigAttributeField="configAttribute"
	
	/** login user class fields (default user class = Person)*/
	def loginUserDomainClass="Person"
	def userName="username"
	def password="passwd"
	def enabled="enabled"
	def relationalAuthorities = "authorities"
	
	/**
	 * Authority domain class authority field name 
	 * authorityFieldInList
	 */
	def authorityField="authority"

	/** authenticationProcessingFilter */
	def authenticationFailureUrl = "/login/authfail?login_error=1"
	def defaultTargetUrl = "/"
	def filterProcessesUrl = "/j_acegi_security_check"

	/** anonymousProcessingFilter */
	def key = "foo"
	def userAttribute = "anonymousUser,ROLE_ANONYMOUS"

	/** authenticationEntryPoint */
	def loginFormUrl="/login/auth"
	def forceHttps="false"
	
	/** accessDeniedHandler 
	 *  set errorPage to null, if you want to get error code 403 (FORBIDDEN).
	 */
	def errorPage="/login/denied"

	/** LoggerListener 
	 * ( add "log4j.logger.org.acegisecurity=info,stdout" to log4j.*.properties to see logs ) 
	 */
	def useLogger = true

	/** use RequestMap from DomainClass */
	def useRequestMapDomainClass = true
	
	/** if useRequestMapDomainClass is false */
	def requestMapString = """
CONVERT_URL_TO_LOWERCASE_BEFORE_COMPARISON
PATTERN_TYPE_APACHE_ANT

/login/**=IS_AUTHENTICATED_ANONYMOUSLY
/admin/**=ROLE_USER
/book/test/**=IS_AUTHENTICATED_FULLY
/book/**=ROLE_SUPERVISOR
/**=IS_AUTHENTICATED_ANONYMOUSLY
"""

}



