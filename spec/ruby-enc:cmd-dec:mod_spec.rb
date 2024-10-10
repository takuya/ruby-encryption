RSpec.describe 'decrypt/encrypt wrapping to ruby module -enc -aes-256-cbc ' do
  file = 'my.txt'
  enc_file = 'my.enc'
  out_file = 'my.out'
  pass = 'your_password_here'
  salt_str = '26CF3DE5072B9BFA'
  salt = [salt_str].pack('H*')
  iter_cnt = 1000 * 10

  ### no base 64
  it 'encrypt(openssl) / decrypt(ruby)   no salt, with salted__' do
    with_tmpdir do |dir|
      open(file, 'w') { |f| f.puts "##### this is a sample file. ##############" }
      OpenSSLEncryption.encrypt_by_openssl(passphrase: pass, file_in: file, file_out: enc_file, iterations: iter_cnt)
      OpenSSLEncryption.decrypt_by_ruby(passphrase: pass, file_enc: enc_file, file_out: out_file, iterations: iter_cnt)
      raise 'encrypt(openssl)->decrypt(ruby) failed.' unless open(out_file).read==open(file).read
      expect(open(enc_file).read[0, 8]).to match /^Salted__/
    end
  end

  it 'encrypt(openssl) / decrypt(ruby) with salt, with salted__' do
    with_tmpdir do |dir|
      open(file, 'w') { |f| f.puts "##### this is a sample file. ##############" }
      OpenSSLEncryption.encrypt_by_openssl(passphrase: pass, file_in: file, file_out: enc_file, iterations: iter_cnt, salt_str: salt_str, salted: true)
      OpenSSLEncryption.decrypt_by_ruby(passphrase: pass, file_enc: enc_file, file_out: out_file, iterations: iter_cnt)
      raise 'encrypt(openssl)->decrypt(ruby) failed.' unless open(out_file).read==open(file).read
      expect(open(enc_file).read[0, 8]).to match /^Salted__/
    end
  end

  it 'encrypt(openssl) / decrypt(ruby) with salt,   no salted__' do
    with_tmpdir do |dir|
      open(file, 'w') { |f| f.puts "##### this is a sample file. ##############" }
      OpenSSLEncryption.encrypt_by_openssl(passphrase: pass, file_in: file, file_out: enc_file, iterations: iter_cnt, salt_str: salt_str, salted: false)
      OpenSSLEncryption.decrypt_by_ruby(passphrase: pass, file_enc: enc_file, file_out: out_file, iterations: iter_cnt, salt: salt)
      raise 'encrypt(ruby)->decrypt(openssl) failed.' unless open(out_file).read==open(file).read
    end
  end

  ## base64
  it 'encrypt(openssl) / decrypt(ruby)   no salt, with salted__, base64' do
    with_tmpdir do |dir|
      open(file, 'w') { |f| f.puts "##### this is a sample file. ##############" }
      OpenSSLEncryption.encrypt_by_openssl(passphrase: pass, file_in: file, file_out: enc_file, iterations: iter_cnt, base64: true)
      OpenSSLEncryption.decrypt_by_ruby(passphrase: pass, file_enc: enc_file, file_out: out_file, iterations: iter_cnt, base64: true)
      raise 'encrypt(openssl)->decrypt(ruby) failed.' unless open(out_file).read==open(file).read
      expect(open(enc_file).read[0, 8]).to match /^#{Base64.encode64('Salted').strip}/
    end
  end
  it 'encrypt(openssl) / decrypt(ruby) with salt, with salted__, base64' do
    with_tmpdir do |dir|
      open(file, 'w') { |f| f.puts "##### this is a sample file. ##############" }
      OpenSSLEncryption.encrypt_by_openssl(passphrase: pass, file_in: file, file_out: enc_file, iterations: iter_cnt, salt_str: salt_str, salted: true, base64: true)
      OpenSSLEncryption.decrypt_by_ruby(passphrase: pass, file_enc: enc_file, file_out: out_file, iterations: iter_cnt, base64: true)
      raise 'encrypt(openssl)->decrypt(ruby) failed.' unless open(out_file).read==open(file).read
      expect(open(enc_file).read[0, 8]).to match /^#{Base64.encode64('Salted').strip}/
    end
  end
  #
  it 'encrypt(openssl) / decrypt(ruby) with salt,   no salted__, base64' do
    with_tmpdir do |dir|
      open(file, 'w') { |f| f.puts "##### this is a sample file. ##############" }
      OpenSSLEncryption.encrypt_by_openssl(passphrase: pass, file_in: file, file_out: enc_file, iterations: iter_cnt, salt_str: salt_str, salted: false, base64: true)
      OpenSSLEncryption.decrypt_by_ruby(passphrase: pass, file_enc: enc_file, file_out: out_file, iterations: iter_cnt, salt: salt, base64: true)
      raise 'encrypt(openssl)->decrypt(ruby) failed.' unless open(out_file).read==open(file).read
    end
  end

end