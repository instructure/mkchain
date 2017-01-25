Gem::Specification.new do |s|
  s.name = 'mkchain'
  s.version = '1.0.2'
  s.authors = ['David Adams']
  s.email = 'dadams@instructure.com'
  s.date = Time.now.strftime('%Y-%m-%d')
  s.license = 'MIT'
  s.homepage = 'https://github.com/instructure/mkchain'
  s.required_ruby_version = '>=2.0.0'

  s.summary = 'Create a chain file from SSL cert'
  s.description =
    'Creates an intermediate chain file from the given SSL certificate'

  s.require_paths = ['lib']
  s.files = [
    'lib/mkchain.rb',
    'README.md',
    'mkchain.gemspec'
  ]
  s.bindir = 'bin'
  s.executables = ['mkchain']
end
