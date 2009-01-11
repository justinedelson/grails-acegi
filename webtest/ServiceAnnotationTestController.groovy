class ServiceAnnotationTestController {

	def annotatedService

	def index = {
		annotatedService.allMethod()
		render 'anyone can see this'
	}

	def admin = {
		annotatedService.adminMethod()
		render 'secure only'
	}
}
