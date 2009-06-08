package test

class TestUser {

	static transients = ['pass']
	static hasMany = [authorities: TestRole]
	static belongsTo = TestRole

	String username
	String passwd
	boolean enabled

	String pass = '[secret]'

	static constraints = {
		username(blank: false, unique: true)
		passwd(blank: false)
	}
}
