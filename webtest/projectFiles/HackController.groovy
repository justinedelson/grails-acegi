import groovy.sql.Sql

class HackController {
	
	def dataSource

	def getSessionValue = {
		def value = session[params.name]
		render value ? value.toString() : ''
	}

	def getSessionNames = {
		session.nowdate = new Date() // to test it's working

		def sb = new StringBuilder()
		session.attributeNames.each { String name ->
			sb.append name
			sb.append '<br/>\n'
		}
		render sb.toString()
	}

	def executeQuery = {
		String query = params.sql
		Sql sql = new Sql(dataSource)
		def result = sql.firstRow(query)[0]
		render result ? result.toString() : ''
	}
}
