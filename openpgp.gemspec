# -*- encoding: utf-8 -*-
require File.expand_path('../lib/openpgp/version', __FILE__)

Gem::Specification.new do |gem|
  gem.version = OpenPGP::VERSION
  gem.date    = Time.now.strftime('%Y-%m-%d')

  gem.name        = 'openpgp'
  gem.authors     = ['Arto Bendiken']
  gem.email       = 'arto.bendiken@gmail.com'
  gem.homepage    = 'http://openpgp.rubyforge.org/'
  gem.license     = 'Public Domain'

  gem.summary     = 'A pure-Ruby implementation of the OpenPGP Message Format (RFC 4880).'
  gem.description = <<-EOF
    OpenPGP.rb is a pure-Ruby implementation of the OpenPGP Message Format
    (RFC 4880), the most widely-used e-mail encryption standard in the world.
  EOF
  gem.rubyforge_project  = 'openpgp'

  gem.executables   = `git ls-files -- bin/*`.split("\n").map{ |f| File.basename(f) }
  gem.files         = `git ls-files`.split("\n")
  gem.test_files    = `git ls-files -- {test,spec,features}/*`.split("\n")
  gem.require_paths = ["lib"]

  gem.has_rdoc  = true

  gem.add_runtime_dependency      'yard'
  gem.add_runtime_dependency      'open4', '>= 1.0.1'
  gem.add_development_dependency  'rspec', '>= 2.7.0'
end
