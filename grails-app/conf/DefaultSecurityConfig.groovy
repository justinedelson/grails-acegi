security {

	/** enable Spring Security or not */
	active = false

	/** login user class fields (default user class = Person)*/
	loginUserDomainClass = 'Person'
	userName = 'username'
	password = 'passwd'
	enabled = 'enabled'
	relationalAuthorities = 'authorities'
	//you can specify method for to retrieve the roles. (you need to set relationalAuthorities=null)
	getAuthoritiesMethod = null // 'getMoreAuthorities'

	/**
	 * Authority domain class authority field name
	 * authorityFieldInList
	 */
	authorityDomainClass = 'Authority'
	authorityField = 'authority'

	/** authenticationProcessingFilter */
	authenticationFailureUrl = '/login/authfail?login_error=1'
	ajaxAuthenticationFailureUrl = '/login/authfail?ajax=true'
	defaultTargetUrl = '/'
	alwaysUseDefaultTargetUrl = false
	filterProcessesUrl = '/j_spring_security_check'
	apf.usernameParameter = 'j_username'
	apf.passwordParameter = 'j_password'
	apf.continueChainBeforeSuccessfulAuthentication = false
	apf.invalidateSessionOnSuccessfulAuthentication = false
	apf.migrateInvalidatedSessionAttributes = true
	apf.allowSessionCreation = true
	apf.serverSideRedirect = false
	apf.exceptionMappings = [:]

	/** daoAuthenticationProvider **/
	reflectionSaltSourceUserProperty = null // if null, don't use salt source

	/** anonymousProcessingFilter */
	key = 'foo'
	userAttribute = 'anonymousUser,ROLE_ANONYMOUS'

	/** authenticationEntryPoint */
	loginFormUrl = '/login/auth'
	forceHttps = 'false'
	ajaxLoginFormUrl = '/login/authAjax'
	loginFormServerSideRedirect = false

	/** logoutFilter */
	afterLogoutUrl = '/'
	logout.filterProcessesUrl = '/j_spring_security_logout'
	logout.useRelativeContext = false

	/** accessDeniedHandler
	 *  set errorPage to null, if you want to get error code 403 (FORBIDDEN).
	 */
	errorPage = '/login/denied'
	ajaxErrorPage = '/login/deniedAjax'
	ajaxHeader = 'X-Requested-With'

	/** passwordEncoder */
	//The digest algorithm to use.
	//Supports the named Message Digest Algorithms in the Java environment.
	//http://java.sun.com/j2se/1.4.2/docs/guide/security/CryptoSpec.html#AppA
	algorithm = 'SHA' // Ex. MD5 SHA
	//use Base64 text ( true or false )
	encodeHashAsBase64 = false

	/** rememberMeServices */
	cookieName = 'grails_remember_me'
	alwaysRemember = false
	tokenValiditySeconds = 1209600 //14 days
	parameter = '_spring_security_remember_me'
	rememberMeKey = 'grailsRocks'

	/** LoggerListener
	 * ( add 'log4j.logger.org.springframework.security=info,stdout'
	 * to log4j.*.properties to see logs )
	 */
	useLogger = false

	/** use RequestMap from DomainClass */
	useRequestMapDomainClass = true

	/** Requestmap domain class (if useRequestMapDomainClass = true) */
	requestMapClass = 'Requestmap'
	requestMapPathField = 'url'
	requestMapConfigAttributeField = 'configAttribute'

	/** use annotations from Controllers to define security rules */
	useControllerAnnotations = false
	controllerAnnotationsMatcher = 'ant' // or 'regex'
	controllerAnnotationsMatchesLowercase = true
	controllerAnnotationStaticRules = [:]
	controllerAnnotationsRejectIfNoRule = false

	/**
	 * if useRequestMapDomainClass is false, set request map pattern in string
	 * see example below
	 */
	requestMapString = """
		CONVERT_URL_TO_LOWERCASE_BEFORE_COMPARISON
		PATTERN_TYPE_APACHE_ANT

		/login/**=IS_AUTHENTICATED_ANONYMOUSLY
		/admin/**=ROLE_USER
		/book/test/**=IS_AUTHENTICATED_FULLY
		/book/**=ROLE_SUPERVISOR
		/**=IS_AUTHENTICATED_ANONYMOUSLY
	"""

	// basic auth
	useBasicAuth = false
	realmName = 'Grails Realm'

	/** use switchUserProcessingFilter */
	switchUserProcessingFilter = false
	swswitchUserUrl = '/j_spring_security_switch_user'
	swexitUserUrl = '/j_spring_security_exit_user'
	swtargetUrl = '/'

	/**use email notification while registration*/
	useMail = false
	mailHost = 'localhost'
	mailUsername = 'user@localhost'
	mailPassword = 'sungod'
	mailProtocol = 'smtp'
	mailFrom = 'user@localhost'
	mailPort = 25

	/** default user's role for user registration */
	defaultRole = 'ROLE_USER'

	// OpenId
	useOpenId = false
	openIdNonceMaxSeconds = 300 // max time between auth start and end

	// LDAP/ActiveDirectory
	useLdap = false
	ldapRetrieveGroupRoles = true
	ldapRetrieveDatabaseRoles = false
	ldapSearchSubtree = true
	ldapGroupRoleAttribute = 'cn'
	ldapPasswordAttributeName = 'userPassword'
	ldapServer = 'ldap://localhost:389' // 'ldap://ad.example.com', 'ldap://monkeymachine:389/dc=acegisecurity,dc=org'
	ldapManagerDn = 'cn=admin,dc=example,dc=com'
	ldapManagerPassword = 'secret'
	ldapSearchBase = 'dc=example,dc=com' // 'ou=users,dc=example,dc=com'
	ldapSearchFilter = '(uid={0})' //, '(mailNickname={0})'
	ldapGroupSearchBase = 'ou=groups,dc=example,dc=com'
	ldapGroupSearchFilter = 'uniquemember={0}'
	ldapUsePassword = true

	// Kerberos
	useKerberos = false
	kerberosLoginConfigFile = 'WEB-INF/jaas.conf'
	kerberosRealm = 'KERBEROS.REALM'
	kerberosKdc = 'krbserver.domain.lan'
	kerberosRetrieveDatabaseRoles = true

	// HttpSessionEventPublisher
	useHttpSessionEventPublisher = false

	// SecurityEventListener
	useSecurityEventListener = false

	// user caching
	cacheUsers = true

	// CAS
	useCAS = false
	cas.casServer = 'localhost'
	cas.casServerPort = '443'
	cas.casServerSecure = true
	cas.localhostSecure = true
	cas.failureURL = '/denied.jsp'
	cas.defaultTargetURL = '/'
	cas.fullLoginURL = 'https://localhost:443/cas/login'
	cas.fullServiceURL = 'https://localhost:443/cas'
	cas.authenticationProviderKey = 'cas_key_changeme'
	cas.userDetailsService = 'userDetailsService'
	cas.sendRenew = false
	cas.proxyReceptorUrl = '/secure/receptor'
	cas.filterProcessesUrl = '/j_spring_cas_security_check'

	// NTLM
	useNtlm = false
	ntlm.stripDomain = true
	ntlm.retryOnAuthFailure = true
	ntlm.forceIdentification = false
	ntlm.defaultDomain = null // set in SecurityConfig.groovy
	ntlm.netbiosWINS = null // set in SecurityConfig.groovy

	// port mappings
	httpPort = 8080
	httpsPort = 8443

	// secure channel filter (http/https)
	secureChannelDefinitionSource = ''
	channelConfig = [secure: [], insecure: []]

	// ip restriction filter
	ipRestrictions = [:]

	// Facebook Connect
	useFacebook = false
	facebook.filterProcessesUrl = '/j_spring_facebook_security_check'
	facebook.authenticationUrlRoot = 'http://www.facebook.com/login.php?v=1.0&api_key='
	facebook.apiKey = '' // set in SecurityConfig
	facebook.secretKey = '' // set in SecurityConfig

	// X509
	useX509 = false
	x509.continueFilterChainOnUnsuccessfulAuthentication = true
	x509.subjectDnRegex = 'CN=(.*?),'

	// authenticationTrustResolver
	atr.anonymousClass = org.springframework.security.providers.anonymous.AnonymousAuthenticationToken
	atr.rememberMeClass = org.springframework.security.providers.rememberme.RememberMeAuthenticationToken

	// misc
	useDaoAuthenticationProviderWithCustomProviders = false
}
