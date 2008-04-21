class BootStrap {

	def exceptionHandler

	def init = { servletContext ->
		exceptionHandler.exceptionMappings = [
			'org.codehaus.groovy.runtime.InvokerInvocationException': '/accessDenied',
			'Exception': '/error'
		]
	}

	def destroy = {
	}
}

