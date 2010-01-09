package test

/**
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
class TestUser {

	static transients = ['pass', 'roleNames']
	static hasMany = [roles: TestRole]
	static belongsTo = TestRole

	String loginName
	String passwrrd
	boolean enabld

	String pass = '[secret]'

	Collection<String> getRoleNames() { roles ? roles*.auth : [] }

	static constraints = {
		loginName blank: false, unique: true
		passwrrd blank: false
	}
}
