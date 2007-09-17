/**
 * Sample domain class for Authority
 * @author T.Yamamoto
 */
class Authority {

	static hasMany=[people:Person]

	/** description */
	String description
	/** ROLE String */
	String authority="ROLE_"

	static def constraints = {
		authority(blank:false)
		description()
	}
}