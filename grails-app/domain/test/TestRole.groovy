package test

/**
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
class TestRole {

	static hasMany = [people: TestUser]

	String description
	String auth

	static constraints = {
		auth blank: false, unique: true
	}
}
