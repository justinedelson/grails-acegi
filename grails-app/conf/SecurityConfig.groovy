// for testing only, not included in plugin zip
security {

	active = true

	loginUserDomainClass = 'test.TestUser'
	userName = 'loginName'
	password = 'passwrrd'
	enabled = 'enabld'
	relationalAuthorities = 'roles'

	authorityDomainClass = 'test.TestRole'
	authorityField = 'auth'

	requestMapClass = 'test.TestRequestmap'
	requestMapPathField = 'urlPattern'
	requestMapConfigAttributeField = 'rolePattern'
}
