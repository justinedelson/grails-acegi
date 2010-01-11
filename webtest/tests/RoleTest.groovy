class RoleTest extends AbstractSecurityWebTest {

	void testRoleListNewDelete() {

		get '/testRole'
		assertContentContains 'Home'

		verifyListSize 0

		click 'New TestRole'
		assertContentContains 'Create TestRole'

		form {
			authority = 'test'
			description = 'test role'
		}
		clickButton 'Create'

		assertContentContains 'Show TestRole'
		click 'TestRole List'

		verifyListSize 1

		get '/testRole/show/1'
		clickButton 'Edit'
		assertContentContains 'Edit TestRole'

		form {
			authority = 'test_new'
			description = 'test role 2'
		}
		clickButton 'Update'

		assertContentContains 'Show TestRole'
		click 'TestRole List'

		verifyListSize 1

		get '/testRole/show/1'
		clickButton 'Delete'
		verifyXPath "//div[@class='message']", ".*TestRole.*deleted.*", true

		verifyListSize 0
	}
}
