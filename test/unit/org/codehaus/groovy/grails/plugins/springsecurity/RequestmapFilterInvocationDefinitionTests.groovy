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

import org.easymock.EasyMockimport org.hibernate.Query
import org.hibernate.SessionFactory
import org.hibernate.classic.Sessionimport org.springframework.mock.web.MockFilterChain
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse
import org.springframework.security.intercept.web.FilterInvocation
import org.springframework.security.util.AntUrlPathMatcher
/**
 * Unit tests for RequestmapFilterInvocationDefinition.
 *
 * @author <a href='mailto:beckwithb@studentsonly.com'>Burt Beckwith</a>
 */
class RequestmapFilterInvocationDefinitionTests extends AbstractSecurityTest {

	private _fid = new RequestmapFilterInvocationDefinition()

	void testSplit() {
		assertArrayEquals(['a', 'b', 'c', 'd', 'e'] as String[], _fid.split('a, b,,,c ,d,e')) 
	}

	void testLoadRequestmaps() {

		_fid.requestMapClass = 'Requestmap'
		_fid.requestMapPathFieldName = 'path'
		_fid.requestMapConfigAttributeField = 'config'

		def instances = [new TestRequestmap(path: 'path1', config: 'config1'),
		                 new TestRequestmap(path: 'path2', config: 'config2'),
		                 new TestRequestmap(path: 'path3', config: 'config3')]
		def sessionFactory = EasyMock.createMock(SessionFactory)
		def session = EasyMock.createMock(Session)
		def query = EasyMock.createMock(Query)
		EasyMock.expect(sessionFactory.openSession()).andReturn(session)
		EasyMock.expect(session.createQuery('FROM Requestmap')).andReturn(query)
		EasyMock.expect(query.list()).andReturn(instances)
		EasyMock.replay sessionFactory, session, query

		_fid.sessionFactory = sessionFactory
		_fid.@_requestmapClass = TestRequestmap
		_fid.findGetters()

		def requestmaps = _fid.loadRequestmaps()
		assertEquals 3, requestmaps.size()
		assertEquals 'config1', requestmaps.path1
		assertEquals 'config2', requestmaps.path2
		assertEquals 'config3', requestmaps.path3

		EasyMock.verify sessionFactory, session, query
	}

	void testAfterPropertiesSet() {
		assertEquals 'url matcher is required', shouldFail(IllegalArgumentException) {
			_fid.afterPropertiesSet()
		}

		_fid.urlMatcher = new AntUrlPathMatcher()

		assertEquals 'Requestmap class name is required', shouldFail(IllegalArgumentException) {
			_fid.afterPropertiesSet()
		}

		_fid.requestMapClass = 'Requestmap'

		assertEquals 'Requestmap path field name is required', shouldFail(IllegalArgumentException) {
			_fid.afterPropertiesSet()
		}

		_fid.requestMapPathFieldName = 'path'

		assertEquals 'Requestmap config attribute field name is required', shouldFail(IllegalArgumentException) {
			_fid.afterPropertiesSet()
		}

		_fid.requestMapConfigAttributeField = 'config'

		assertEquals 'sessionFactory is required', shouldFail(IllegalArgumentException) {
			_fid.afterPropertiesSet()
		}

		def sessionFactory = EasyMock.createMock(SessionFactory)
		EasyMock.replay sessionFactory

		_fid.sessionFactory = sessionFactory

		_fid.@_requestmapClass = TestRequestmap

		_fid.afterPropertiesSet()

		EasyMock.verify sessionFactory
	}

	void testStoreMapping() {
		_fid.urlMatcher = new AntUrlPathMatcher()

		assertEquals 0, _fid.configAttributeMap.size()

		_fid.storeMapping '/foo/bar', 'ROLE_ADMIN' as String[]
		assertEquals 1, _fid.configAttributeMap.size()

		_fid.storeMapping '/foo/bar', 'ROLE_USER' as String[]
		assertEquals 1, _fid.configAttributeMap.size()

		_fid.storeMapping '/other/path', 'ROLE_SUPERUSER' as String[]
		assertEquals 2, _fid.configAttributeMap.size()
	}

	void testReset() {
		_fid = new TestRequestmapFilterInvocationDefinition()
		_fid.urlMatcher = new AntUrlPathMatcher()

		assertEquals 0, _fid.configAttributeMap.size()

		_fid.reset()

		assertEquals 2, _fid.configAttributeMap.size()
	}

	void testInitialize() {
		_fid = new TestRequestmapFilterInvocationDefinition()
		_fid.urlMatcher = new AntUrlPathMatcher()

		assertEquals 0, _fid.configAttributeMap.size()

		_fid.initialize()
		assertEquals 2, _fid.configAttributeMap.size()

		_fid.@_compiled.clear()

		_fid.initialize()
		assertEquals 0, _fid.configAttributeMap.size()
	}

	void testDetermineUrl() {
		_fid.urlMatcher = new AntUrlPathMatcher()

		def request = new MockHttpServletRequest()
		def response = new MockHttpServletResponse()
		def chain = new MockFilterChain()
		request.contextPath = '/context'

		request.requestURI = '/context/foo'
		assertEquals '/foo', _fid.determineUrl(new FilterInvocation(request, response, chain))

		request.requestURI = '/context/fOo/Bar?x=1&y=2'
		assertEquals '/foo/bar', _fid.determineUrl(new FilterInvocation(request, response, chain))
	}
}

class TestRequestmap {
	String path
	String config
}

class TestRequestmapFilterInvocationDefinition extends RequestmapFilterInvocationDefinition {
	protected Map<String, String> loadRequestmaps() {
		['/foo/bar': 'ROLE_USER', '/admin/**': 'ROLE_ADMIN']
	}
}
