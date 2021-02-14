# -*- encoding: utf-8 -*-

lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)

Gem::Specification.new do |spec|
  spec.name          = "fluent-plugin-aws-elasticsearch-service-build"
  spec.version       = "1.1.19"
  spec.authors       = ["Anwarulhaq"]
  spec.email         = ["ulhaqanwar794@gmail.com"]

  spec.summary       = %q{"Amazon Elasticsearch Service" Output Plugin Using Access, Secret and session Key to communicate.}
  spec.license       = "MIT"


  spec.files         = `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_development_dependency "bundler", "~> 1.10"
  spec.add_development_dependency "rake", "~> 10.0"
  spec.add_development_dependency "rspec", "~> 3.0"
  spec.add_development_dependency "test-unit", "~> 3.0"
  spec.add_runtime_dependency "fluentd", "~> 0"
  spec.add_runtime_dependency "fluent-plugin-elasticsearch", "~> 2.0.0.rc.1"
  spec.add_runtime_dependency "aws-sdk", "~> 2"
  spec.add_runtime_dependency "faraday_middleware-aws-signers-v4", ">= 0.1.0", "< 0.1.2"
end
