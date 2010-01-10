grails.project.class.dir = 'target/classes'
grails.project.plugins.dir = 'plugins'
grails.project.test.class.dir = 'target/test-classes'
grails.project.test.reports.dir	= 'target/test-reports'

grails.project.dependency.resolution = {
	inherits('global')
	log 'warn'
	repositories {
		grailsPlugins()
		grailsHome()
	}
	dependencies {}
}

coverage {
	enabledByDefault = true
	sourceInclusions = ['grails-app/conf', 'grails-app/jobs']
	exclusionListOverride = [
		'*GrailsPlugin*',
		'DataSource*',
		'BuildConfig*',
		'DefaultSecurityConfig*',
		'SecurityConfig*',
		'test/**'
	]
}
