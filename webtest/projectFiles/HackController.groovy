class HackController {

	def getSessionValue = {
		def value = session[params.name]
		render value ? value.toString() : ''
	}

	def getSessionNames = {
		session.nowdate = new Date()
		def sb = new StringBuilder()
		session.attributeNames.each { String name ->
			sb.append name
			sb.append '<br/>\n'
		}
		render sb.toString()
	}
}

