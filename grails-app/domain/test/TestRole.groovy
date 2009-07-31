package test

/**
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
class TestRole {

	static hasMany = [people: TestUser]

	String description
	String authority

	static constraints = {
		authority(blank: false, unique: true)
		description()
	}
}
