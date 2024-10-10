# frozen_string_literal: true

require 'pry'
require 'tmpdir'
require 'base64'
require_relative '../lib/openssl/utils'

def with_tmpdir
  Dir.mktmpdir do |dir|
    Dir.chdir(dir) do
      yield dir
    end
  end
end

RSpec.configure do |config|
  # Enable flags like --only-failures and --next-failure
  config.example_status_persistence_file_path = ".rspec_status"

  # Disable RSpec exposing methods globally on `Module` and `main`
  config.disable_monkey_patching!

  config.expect_with :rspec do |c|
    c.syntax = :expect
  end
end

