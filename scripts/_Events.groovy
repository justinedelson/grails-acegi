// for some reason compiling AcegiGrailsPlugin.groovy confuses code coverage even with proper
// exclusions, so make sure there's an existing AcegiGrailsPlugin.class so the descriptor isn't compiled
eventCompileStart = {
	ant.mkdir(dir: classesDirPath)
	ant.copy(file: 'AcegiGrailsPlugin.class.coveragefix', tofile: "$classesDirPath/AcegiGrailsPlugin.class")
}
