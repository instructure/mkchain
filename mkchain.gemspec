# frozen_string_literal: true

require_relative 'lib/mkchain'

Gem::Specification.new do |s|
  s.name = 'mkchain'
  s.version = MkChain::VERSION
  s.authors = ['David Adams', 'David Warkentin']
  s.email = ['dadams@instructure.com', 'dwarkentin@instructure.com']
  s.license = 'MIT'
  s.homepage = 'https://github.com/instructure/mkchain'
  s.required_ruby_version = '>=3.0.0'

  s.summary = 'Create a chain file from SSL cert'
  s.description =
    'Creates an intermediate chain file from the given SSL certificate'

  s.metadata = {
    'rubygems_mfa_required' => 'true',
    'source_code_uri' => s.homepage,
  }

  s.require_paths = ['lib']
  s.files = Dir.chdir(File.expand_path(__dir__)) do
    Dir.glob('lib/**/*.rb') +
      Dir.glob('bin/*') +
      %w[README.md LICENSE mkchain.gemspec]
  end
  s.bindir = 'bin'
  s.executables = ['mkchain']
end
