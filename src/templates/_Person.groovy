${personClassPackage}

${authorityClassImport}

/**
 * User domain class.
 */
class ${personClassName} {
	static transients = ['pass']
	static hasMany = [authorities: ${authorityClassName}]
	static belongsTo = ${authorityClassName}

	/** Username */
	String username
	/** User Real Name*/
	String userRealName
	/** encrypted Password */
	String passwd
	/** enabled */
	boolean enabled

	String email
	boolean emailShow

	/** description */
	String description = ''

	/** plain password to create an encrypted password */
	String pass = '[secret]'

	static constraints = {
		username(blank: false, unique: true)
		userRealName(blank: false)
		passwd(blank: false)
		enabled()
	}
}
