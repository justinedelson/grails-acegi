grails.project.plugins.dir = 'plugins'

//coverage.sourceInclusions = ['grails-app/conf', 'grails-app/jobs']

coverage.enabledByDefault = true

coverage.exclusionListOverride = [
	'*GrailsPlugin*',
	'DataSource*',
	'BuildConfig*',
	'DefaultSecurityConfig*',
	'SecurityConfig*',
	'test/**'
]
