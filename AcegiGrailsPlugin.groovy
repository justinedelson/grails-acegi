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
 * Grails Acegi Security Plugin
 * 
 * @author T.Yamamoto
 * 
 */
class AcegiGrailsPlugin {
	def version = 0.1
	def dependsOn = [:]
	def configExist = false
	
	def doWithSpring = {
		def cf={field->
			return "get"+field[0].toUpperCase()+field[1..<field.length()]
		}
		/** init from a conf class */
		//def conf = application.getController("LoginController").newInstance()
		def conf = application.getArtefact("Controller","LoginController").newInstance()
		if(conf!=null){
			println conf.loadMessage
			configExist=true
		}else{
			println "Acegi on Grails Configurations are not loaded..."
		}

		//if LoginController's config exists
		if(configExist){
			/** filter list */
			def filters = 
				["httpSessionContextIntegrationFilter",
					"logoutFilter",
					"authenticationProcessingFilter",
					"securityContextHolderAwareRequestFilter",
				//	"rememberMeProcessingFilter",
					"anonymousProcessingFilter",
					"exceptionTranslationFilter",
					"filterInvocationInterceptor"]

			/** filterChainProxy */
			filterChainProxy(org.acegisecurity.util.FilterChainProxy){
				filterInvocationDefinitionSource="""
					CONVERT_URL_TO_LOWERCASE_BEFORE_COMPARISON
					PATTERN_TYPE_APACHE_ANT
					/**=${filters.join(',')}
					"""
			}

			/** httpSessionContextIntegrationFilter */
			httpSessionContextIntegrationFilter(org.acegisecurity.context.HttpSessionContextIntegrationFilter){}

			/** logoutFilter */
			def list = new org.acegisecurity.ui.logout.LogoutHandler[1]
			//TODO rememberMeServices on logoutFilter
			//list[0]=ref("rememberMeServices")
			list[0]=new org.acegisecurity.ui.logout.SecurityContextLogoutHandler()

			logoutFilter(org.acegisecurity.ui.logout.LogoutFilter,"/",list){}

			/** authenticationProcessingFilter */
			authenticationProcessingFilter(org.acegisecurity.ui.webapp.AuthenticationProcessingFilter){
				authenticationManager = ref("authenticationManager")
				authenticationFailureUrl = conf.authenticationFailureUrl //"/login/authfail?login_error=1"
				defaultTargetUrl = conf.defaultTargetUrl // "/"
				filterProcessesUrl = conf.filterProcessesUrl //"/j_acegi_security_check"
				//	rememberMeServices = ref("rememberMeServices")
			}

			/** securityContextHolderAwareRequestFilter */
			securityContextHolderAwareRequestFilter(org.acegisecurity.wrapper.SecurityContextHolderAwareRequestFilter){}

			/** anonymousProcessingFilter */
			anonymousProcessingFilter(org.acegisecurity.providers.anonymous.AnonymousProcessingFilter){
				key = conf.key // "foo"
				userAttribute = conf.userAttribute //"anonymousUser,ROLE_ANONYMOUS"
			}

				/** rememberMeProcessingFilter */
		//		rememberMeProcessingFilter(org.acegisecurity.ui.rememberme.RememberMeProcessingFilter){
		//			authenticationManager=ref("authenticationManager")
		//			rememberMeServices=ref("rememberMeServices")
		//		}
				/** rememberMeServices */
		//		rememberMeServices(org.acegisecurity.ui.rememberme.TokenBasedRememberMeServices){
		//			userDetailsService=ref("userDetailsService")
		//			key="grailsRocks"
		//		}

			/** exceptionTranslationFilter */
			exceptionTranslationFilter(org.acegisecurity.ui.ExceptionTranslationFilter){
				authenticationEntryPoint=ref("authenticationEntryPoint")
				accessDeniedHandler=ref("accessDeniedHandler")
			}

			authenticationEntryPoint(org.acegisecurity.ui.webapp.AuthenticationProcessingFilterEntryPoint){
				loginFormUrl= conf.loginFormUrl // "/login/auth"
				forceHttps= conf.forceHttps // "false"
			}
			accessDeniedHandler(org.codehaus.groovy.grails.plugins.acegi.GrailsAccessDeniedHandlerImpl){
				errorPage= conf.errorPage // "/login/denied"
			}

			/** filterInvocationInterceptor */
			filterInvocationInterceptor(org.acegisecurity.intercept.web.FilterSecurityInterceptor){
				authenticationManager=ref("authenticationManager")
				accessDecisionManager=ref("accessDecisionManager")
				if( conf.useRequestMapDomainClass ){
					objectDefinitionSource=ref("objectDefinitionSource")
				}else{
					objectDefinitionSource=conf.requestMapString
				}
			}

			/** accessDecisionManager */
			accessDecisionManager(org.acegisecurity.vote.AffirmativeBased){
				allowIfAllAbstainDecisions="false"
				decisionVoters=[
					ref("roleVoter"),
					ref("authenticatedVoter")]
			}
			roleVoter(org.acegisecurity.vote.RoleVoter){}
			authenticatedVoter(org.acegisecurity.vote.AuthenticatedVoter){}

			if( conf.useRequestMapDomainClass ){
				/** objectDefinitionSource */
				objectDefinitionSource(org.codehaus.groovy.grails.plugins.acegi.GrailsFilterInvocationDefinition){
					loginControllerName= conf.loginControllerName // "LoginController"
					loginControllerRequestMapMethod= conf.loginControllerRequestMapMethod // "requestMap"
					requestMapClass= conf.requestMapClass // "Requestmap"
					requestMapPathFieldMethod= cf(conf.requestMapPathField) // "getUrl"
					requestMapConfigAttributeFieldMethod= cf(conf.requestMapConfigAttributeField) // "getConfig_attribute"
					requestMapPathFieldName= conf.requestMapPathField // "url"
				}
			}

			/** ProviderManager */
			authenticationManager(org.acegisecurity.providers.ProviderManager){
				providers=[
					ref("daoAuthenticationProvider"),
					ref("anonymousAuthenticationProvider")]
					//ref("rememberMeAuthenticationProvider")]
			}

			/** daoAuthenticationProvider */
			daoAuthenticationProvider(org.acegisecurity.providers.dao.DaoAuthenticationProvider){
				userDetailsService=ref("userDetailsService")
				passwordEncoder=ref("passwordEncoder")
				userCache=ref("userCache")
			}

			/** userCache */
			userCache(org.acegisecurity.providers.dao.cache.EhCacheBasedUserCache){
				cache=ref("cache")
			}
			cache(org.springframework.cache.ehcache.EhCacheFactoryBean){
				cacheManager=ref("cacheManager")
				cacheName="userCache"
			}
			cacheManager(org.springframework.cache.ehcache.EhCacheManagerFactoryBean){}

			/** anonymousAuthenticationProvider */
			anonymousAuthenticationProvider(org.acegisecurity.providers.anonymous.AnonymousAuthenticationProvider){
				key= conf.key // "foo"
			}
			/** rememberMeAuthenticationProvider */
			//rememberMeAuthenticationProvider(org.acegisecurity.providers.rememberme.RememberMeAuthenticationProvider){
				//key="grailsRocks"
			//}

			/** passwordEncoder */
			passwordEncoder(org.acegisecurity.providers.encoding.Md5PasswordEncoder){}
			/** DetailsService */
			userDetailsService(org.codehaus.groovy.grails.plugins.acegi.GrailsDaoImpl){
				userName= conf.userName[0].toUpperCase()+conf.userName[1..<conf.userName.length()]//cf(conf.userName) // "getUsername"
				password= cf(conf.password) // "getPasswd"
				enabled= cf(conf.enabled) // "getEnabled"

				authority= cf(conf.authorityField) // "getAuthority"
				loginUserDomainClass=conf.loginUserDomainClass //"Person"
				relationalAuthorities=cf(conf.relationalAuthorities)
			}

			/** LoggerListener ( log4j.logger.org.acegisecurity=info,stdout ) */
			if(conf.useLogger){
				loggerListener(org.acegisecurity.event.authentication.LoggerListener){}
			}

		}//end if(_go)
	}

	def doWithApplicationContext = { applicationContext ->
		// TODO Implement post initialization spring config (optional)		
	}

	def doWithWebDescriptor = {webXml ->
		/** TODO: Check can use acegi or not 
		def conf = application.getController("LoginController").newInstance()
		if(conf!=null){
			println conf.loadMessage
			_go=true
		}else{
			println "Acegi on Grails Configurations are not loaded..."
		}*/

		configExist=true
		if(configExist){
			def contextParam = webXml."context-param"
			contextParam[contextParam.size()-1]+{
				'filter' {
					//'filter-name'('acegiAuthenticationProcessingFilter')
					//'filter-class'('org.acegisecurity.util.FilterToBeanProxy')
					'filter-name'('filterChainProxy')
					'filter-class'('org.springframework.web.filter.DelegatingFilterProxy')
					'init-param'{
						'param-name'('targetClass')
						'param-value'('org.acegisecurity.util.FilterChainProxy')
					}
				}
			}

			def filter = webXml."filter"
			filter[filter.size()-1]+{
				'filter-mapping'{
					//'filter-name'('acegiAuthenticationProcessingFilter')
					'filter-name'('filterChainProxy')
					'url-pattern'("/*")
				}
			}
		}
	}

	def onChange = { event ->
	}                                                                                  
	def onApplicationChange = { event ->
	}



}
