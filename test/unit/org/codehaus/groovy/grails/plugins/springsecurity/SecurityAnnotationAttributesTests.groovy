/* Copyright 2006-2009 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.codehaus.groovy.grails.plugins.springsecurity

import org.springframework.security.annotation.Secured

/**
 * Unit tests for SecurityAnnotationAttributes.
 *
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
class SecurityAnnotationAttributesTests extends AbstractSecurityTest {

	private _attributes = new SecurityAnnotationAttributes()

	void testGetAttributesClass() {
		assertEquals 1, _attributes.getAttributes(Annotated).size()
		assertEquals 0, _attributes.getAttributes(NotAnnotated).size()
	}

	void testGetAttributesMethod() {
		def notAnnotated = Annotated.methods.find { it.name == 'notAnnotated' }
		assertEquals 0, _attributes.getAttributes(notAnnotated).size()

		def annotated1 = Annotated.methods.find { it.name == 'annotated1' }
		assertEquals 1, _attributes.getAttributes(annotated1).size()

		def annotated2 = Annotated.methods.find { it.name == 'annotated2' }
		assertEquals 2, _attributes.getAttributes(annotated2).size()
	}

	void testGetAttributesClassClass() {
		shouldFail(UnsupportedOperationException) {
			_attributes.getAttributes Annotated, Annotated
		}
	}

	void testGetAttributesMethodClass() {
		shouldFail(UnsupportedOperationException) {
			_attributes.getAttributes Annotated.methods.find { it.name == 'annotated1' }, Annotated
		}
	}

	void testGetAttributesField() {
		shouldFail(UnsupportedOperationException) {
			_attributes.getAttributes Annotated.declaredFields.find { it.name == 'theField' }
		}
	}

	void testGetAttributesFieldClass() {
		shouldFail(UnsupportedOperationException) {
			_attributes.getAttributes Annotated.declaredFields.find { it.name == 'theField' }, Annotated
		}
	}
}

@Secured(['ROLE_FOO'])
class Annotated {

	private String theField

	@Secured(['ROLE_ADMIN'])
	void annotated1() {}

	@Secured(['ROLE_ADMIN', 'ROLE_SUPERUSER'])
	void annotated2() {}

	void notAnnotated() {}
}

class NotAnnotated {}
