package test

class TestRole {

	static hasMany = [people: TestUser]

	String description
	String authority

	static constraints = {
		authority(blank: false, unique: true)
		description()
	}
}
