${requestmapClassImport}

import org.springframework.util.StringUtils

/**
 * Requestmap controller.
 */
class ${requestmapClassName}Controller {

	// the delete, save and update actions only accept POST requests
	def allowedMethods = [delete: 'POST', save: 'POST', update: 'POST']

	def index = {
		redirect(action: list, params: params)
	}

	def list = {
		if (!params.max) {
			params.max = 10
		}
		[requestmapList: ${requestmapClassName}.list(params)]
	}

	def show = {
		[requestmap: ${requestmapClassName}.get(params.id)]
	}

	def delete = {
		def requestmap = ${requestmapClassName}.get(params.id)
		if (!requestmap) {
			flash.message = "${requestmapClassName} not found with id \${params.id}"
			redirect(action:list)
			return
		}

		requestmap.delete()
		flash.message = "${requestmapClassName} \${params.id} deleted."
		redirect(action: list)
	}

	def edit = {
		def requestmap = ${requestmapClassName}.get(params.id)
		if (!requestmap) {
			flash.message = "${requestmapClassName} not found with id \${params.id}"
			redirect(action: list)
			return
		}

		[requestmap: requestmap]
	}

	/**
	 * Update action, called when an existing Requestmap is updated.
	 */
	def update = {

		def requestmap = ${requestmapClassName}.get(params.id)
		if (!requestmap) {
			flash.message = "${requestmapClassName} not found with id \${params.id}"
			redirect(action: edit, id :params.id)
			return
		}

		updateFromParams(requestmap)
		if (requestmap.save()) {
			redirect(action: show, id: requestmap.id)
		}
		else {
			render(view: 'edit', model: [requestmap: requestmap])
		}
	}

	def create = {
		def requestmap = new ${requestmapClassName}()
		requestmap.properties = params
		[requestmap: requestmap]
	}

	/**
	 * Save action, called when a new Requestmap is created.
	 */
	def save = {

		def requestmap = new ${requestmapClassName}()
		updateFromParams(requestmap)
		if (requestmap.save()) {
			redirect(action: show, id: requestmap.id)
		}
		else {
			render(view: 'create', model: [requestmap: requestmap])
		}
	}

	private void updateFromParams(requestmap) {
		requestmap.properties = params
		//get user's enter field "configAttribute" from the params.
		String[] configAttrs = StringUtils.commaDelimitedListToStringArray(params.configAttribute)
		//Format the configAttributes to meet Spring Security's requirement.
		String formattedConfigAttrs = ''
		String delimiter = ''
		for (String configAttribute in configAttrs) {
			if (configAttribute.trim().length() > 0) {
				formattedConfigAttrs += delimiter + 'ROLE_' + configAttribute.toUpperCase()
				delimiter = ','
			}
		}
		requestmap.configAttribute = formattedConfigAttrs
	}
}
