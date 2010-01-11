class UserTest extends AbstractSecurityWebTest {

	void testUserListNewDelete() {
		get '/testUser'
		assertContentContains 'Home'

		verifyListSize 0

		click 'New TestUser'
		assertContentContains 'Create TestUser'

		form {
			username = 'new_user'
			userRealName = 'new user'
			passwd = 'p4ssw0rd'
			enabled = true
			description = 'a new user'
			email = 'new@user.com'
			emailShow = true
		}
		clickButton 'Create'

		assertContentContains 'Show TestUser'
		click 'TestUser List'

		verifyListSize 1

		get '/testUser/show/1'
		clickButton 'Edit'
		assertContentContains 'Edit TestUser'

		form {
			username = 'new_user2'
			userRealName = 'new user2'
			passwd = 'p4ssw0rd2'
			enabled = false
			description = 'a new user 2'
			email = 'new@user2.com'
			emailShow = false
		}
		clickButton 'Update'

		assertContentContains 'Show TestUser'
		click 'TestUser List'

		verifyListSize 1

		get '/testUser/show/1'
		clickButton 'Delete'
		verifyXPath "//div[@class='message']", ".*TestUser.*deleted.*", true

		verifyListSize 0
	}
}
