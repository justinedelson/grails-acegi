import org.springframework.security.annotation.Secured

class AnnotatedService {

	boolean transactional = true

	static scope = 'request'

	void allMethod() {
		println 'allMethod called'
	}

	@Secured(['ROLE_ADMIN'])
	void adminMethod() {
		println 'adminMethod called'
	}
}
