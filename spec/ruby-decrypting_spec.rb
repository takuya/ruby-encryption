
RSpec.describe 'decrypt/encrypt by ruby equivalent to openssl -enc -aes-256-cbc ' do

  file = 'my.txt'
  enc_file = 'my.enc'
  out_file = 'my.out'
  pass = 'your_password_here'
  salt_str = '26CF3DE5072B9BFA'
  salt = [salt_str].pack('H*')
  iter_cnt = 1000 * 10


  it 'encrypt/decrypt by openssl,  Salted__' do
    with_tmpdir do |dir|
      open(file, 'w') { |f| f.puts "##### this is a sample file. ##############" }
      OpenSSLEncryption.encrypt_by_openssl_salted(passphrase: pass, file_in: file, file_out: enc_file,iterations: iter_cnt, salt_str:salt_str)
      OpenSSLEncryption.decrypt_by_openssl(passphrase: pass, file_in: enc_file, file_out: out_file, iterations: iter_cnt)
      raise 'encrypt(openssl)->decrypt(openssl) failed.' unless open(out_file).read==open(file).read
    end
  end

  it "encrypt/decrypt by openssl , not Salted " do
    with_tmpdir do |dir|
      open(file, 'w') { |f| f.puts "##### this is a sample file. ##############" }
      OpenSSLEncryption.encrypt_by_openssl(passphrase: pass, file_in: file, file_out: enc_file, iterations: iter_cnt, salt_str: salt_str)
      OpenSSLEncryption.decrypt_by_openssl(passphrase: pass, file_in: enc_file, file_out: out_file, iterations: iter_cnt, salt_str: salt_str)
      raise 'encrypt/decrypt by openssl ' unless open(out_file).read==open(file).read
    end
  end
  it "encrypt/decrypt by ruby , not Salted" do
    with_tmpdir do |dir|
      open(file, 'w') { |f| f.puts "##### this is a sample file. ##############" }
      OpenSSLEncryption.encrypt_by_ruby(passphrase: pass, file_in: file, file_out: enc_file, iterations: iter_cnt, salt: salt, salted: false)
      OpenSSLEncryption.decrypt_by_ruby(passphrase: pass, file_enc: enc_file, file_out: out_file, iterations: iter_cnt, salt: salt)
      raise 'encrypt/decrypt by ruby failed.' unless open(out_file).read==open(file).read
    end
  end
  it "encrypt/decrypt by ruby , Salted__" do
    with_tmpdir do |dir|
      open(file, 'w') { |f| f.puts "##### this is a sample file. ##############" }
      OpenSSLEncryption.encrypt_by_ruby(passphrase: pass, file_in: file, file_out: enc_file, iterations: iter_cnt, salt: salt)
      OpenSSLEncryption.decrypt_by_ruby(passphrase: pass, file_enc: enc_file, file_out: out_file, iterations: iter_cnt)
      raise 'encrypt/decrypt by ruby failed.' unless open(out_file).read==open(file).read
    end
  end
  it "encrypt(ruby)->decrypt(openssl) , Salted__" do
    with_tmpdir do |dir|
      open(file, 'w') { |f| f.puts "##### this is a sample file. ##############" }
      OpenSSLEncryption.encrypt_by_ruby(passphrase: pass, file_in: file, file_out: enc_file, iterations: iter_cnt, salt: salt)
      OpenSSLEncryption.decrypt_by_openssl(passphrase: pass, file_in: enc_file, file_out: out_file, iterations: iter_cnt)
      raise 'encrypt(ruby)->decrypt(openssl) failed.' unless open(out_file).read==open(file).read
    end
  end
  it "encrypt(ruby)->decrypt(openssl) , not Salted" do
    with_tmpdir do |dir|
      open(file, 'w') { |f| f.puts "##### this is a sample file. ##############" }
      OpenSSLEncryption.encrypt_by_ruby(passphrase: pass, file_in: file, file_out: enc_file, iterations: iter_cnt, salt: salt, salted: false)
      OpenSSLEncryption.decrypt_by_openssl(passphrase: pass, file_in: enc_file, file_out: out_file, iterations: iter_cnt, salt_str: salt_str)
      raise 'encrypt(ruby)->decrypt(openssl) failed.' unless open(out_file).read==open(file).read
    end
  end
  it 'encrypt(openssl)->decrypt(ruby), not Salted' do
    with_tmpdir do |dir|
      open(file, 'w') { |f| f.puts "##### this is a sample file. ##############" }
      OpenSSLEncryption.encrypt_by_openssl(passphrase: pass, file_in: file, file_out: enc_file,iterations: iter_cnt, salt_str:salt_str)
      OpenSSLEncryption.decrypt_by_ruby(passphrase: pass, file_enc: enc_file, file_out: out_file, iterations: iter_cnt, salt:salt)
      raise 'encrypt(openssl)->decrypt(ruby) failed.' unless open(out_file).read==open(file).read
    end
  end
  it 'encrypt(openssl)->decrypt(ruby), Salted' do
    with_tmpdir do |dir|
      open(file, 'w') { |f| f.puts "##### this is a sample file. ##############" }
      OpenSSLEncryption.encrypt_by_openssl_salted(passphrase: pass, file_in: file, file_out: enc_file,iterations: iter_cnt, salt_str:salt_str)
      OpenSSLEncryption.decrypt_by_ruby(passphrase: pass, file_enc: enc_file, file_out: out_file, iterations: iter_cnt)
      raise 'encrypt(openssl)->decrypt(ruby) failed.' unless open(out_file).read==open(file).read
    end
  end
end
