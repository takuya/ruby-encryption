
require 'openssl'

module OpenSSLEncryption
  class << self
    public
    def encrypt_by_ruby(passphrase:, file_in:, file_out:, iterations:, salt:,salted:true)
      salt ||= OpenSSL::Random.random_bytes(8)
      cipher = OpenSSL::Cipher.new("AES-256-CBC")
      cipher.encrypt
      cipher.iv, cipher.key = pbkdf2_gen_key(passphrase, salt, iterations)

      encrypted_data = cipher.update(open(file_in).read) + cipher.final
      encrypted_data = 'Salted__'+salt + encrypted_data  if salted ## salted 付与
      open(file_out, 'wb') { |f| f.write encrypted_data }
      encrypted_data
    end
    def decrypt_by_ruby(passphrase:, file_enc:, file_out:, iterations:, salt:nil)
      data = open(file_enc).read
      if salt.nil? || data.start_with?('Salted__') ## Salt 取り出し
        salt = data[8,8]
        encrypted_data = data[16,data.size]
      else
        encrypted_data=data
      end

      cipher = OpenSSL::Cipher.new("AES-256-CBC")
      cipher.decrypt
      cipher.iv, cipher.key = pbkdf2_gen_key(passphrase, salt, iterations)

      decrypt_data = cipher.update(encrypted_data) + cipher.final
      open(file_out, 'wb') { |f| f.write decrypt_data }
      decrypt_data
    end
    def decrypt_by_openssl(passphrase:, file_in:, file_out:, iterations:, salt_str:nil)
      ## ファイルからSalt取り出せるので nil でいい
      if salt_str.nil?
        `openssl enc -d -aes-256-cbc -pbkdf2 -iter #{iterations} -in #{file_in} -out #{file_out} -k #{passphrase}`
      elsif salt_str.is_a? String
        `openssl enc -d -aes-256-cbc -pbkdf2 -iter #{iterations} -S #{salt_str} -in #{file_in} -out #{file_out} -k #{passphrase}`
      end
    end

    def encrypt_by_openssl(passphrase:, file_in:, file_out:, iterations:, salt_str:)
      `openssl enc -e -aes-256-cbc -pbkdf2 -iter #{iterations} -S #{salt_str} -in #{file_in} -out #{file_out} -k #{passphrase}`
    end
    def encrypt_by_openssl_salted(passphrase:, file_in:, file_out:, iterations:, salt_str:)
      require 'tempfile'
      Tempfile.open do |tmp_f|
        encrypt_by_openssl(passphrase:, file_in:, file_out:tmp_f.path, iterations:, salt_str:)
        `(echo -n "Salted__"; echo #{salt_str} | xxd -r -p; cat #{tmp_f.path} ) > #{file_out}`
      end
    end

    protected
    def pbkdf2_gen_key(passphrase, salt, iter, key_len = 32, iv_len = 16)
      key_and_iv = OpenSSL::PKCS5.pbkdf2_hmac(passphrase, salt, iter, iv_len + key_len, 'sha256')
      ## 48バイトの key_iv のバイト列が生成される。
      # p key_and_iv.unpack1('H*')
      iv = key_and_iv[key_len, iv_len] # 末尾16バイト取出し
      key = key_and_iv[0, key_len] # 先頭32bytes取出し
      [iv, key]
    end
  end

end