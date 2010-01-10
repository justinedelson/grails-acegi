<%
def e = request.exception
if (e instanceof org.codehaus.groovy.grails.web.errors.GrailsWrappedRuntimeException) {
	e = e.cause
	if (e instanceof org.codehaus.groovy.runtime.InvokerInvocationException) {
		e = e.cause
		if (e instanceof org.springframework.security.AccessDeniedException) {
			response.status = 200
			println "Access is denied"
		}
	}
}
%>
