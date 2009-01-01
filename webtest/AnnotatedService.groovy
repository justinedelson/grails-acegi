import org.springframework.security.annotation.Secured

class AnnotatedService {

	boolean transactional = false

	void allMethod() {
		println 'allMethod called'
	}

	@Secured(['ROLE_ADMIN'])
	void adminMethod() {
		println 'adminMethod called'
	}
}
