# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)

Gem::Specification.new do |spec|
  spec.name          = "bip38"
  spec.version       = "0.0.1"
  spec.authors       = ["Vincent RENAUDINEAU"]
  spec.email         = ["vincent.renaudineau@wanadoo.fr"]
  spec.description   = %q{A Ruby implementation of the BIP-0038 draft for encryption of Bitcoin keys}
  spec.summary       = %q{A Ruby implementation of the BIP-0038 draft for encryption of Bitcoin keys}
  spec.homepage      = "https://github.com/timmy72/ruby-bip38"
  spec.license       = "MIT"

  spec.files         = ["lib/bip38.rb"]
  spec.test_files    = ["specs/bip38_spec.rb", "specs/spec_helper.rb"]
  spec.require_paths = ["lib"]

  spec.add_development_dependency "bundler", "~> 1.3"
end
