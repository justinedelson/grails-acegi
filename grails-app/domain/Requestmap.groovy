
/**
 * Sample domain class for Request Map
 * @author T.Yamamoto 
 */
class Requestmap {

	String url
	String configAttribute

	static def constraints = {
		url(blank:false,unique:true)
		configAttribute(blank:false)
	}
}
