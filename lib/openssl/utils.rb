require 'openssl'
require 'securerandom'
require 'base64'

module OpenSSLEncryption
  class << self
    public

    def encrypt_by_ruby(passphrase:, file_in:, file_out:, iterations:, salt: nil, salted: true,base64:false)
      raise ArgumentError.new("salted:true or salt:not null") if salt.nil? and !salted
      raise ArgumentError.new("salt be 8 bytes") if salt && salt.size!=8
      ##
      salt ||= SecureRandom.random_bytes(8)
      cipher = OpenSSL::Cipher.new("AES-256-CBC")
      cipher.encrypt
      cipher.iv, cipher.key = pbkdf2_gen_key(passphrase, salt, iterations)
      ##
      encrypted_data = cipher.update(open(file_in).read) + cipher.final
      encrypted_data = 'Salted__' + salt + encrypted_data if salted ## salted 付与
      encrypted_data = Base64.encode64(encrypted_data).strip if base64
      open(file_out, 'wb') { |f| f.write encrypted_data }
      encrypted_data
    end

    def decrypt_by_ruby(passphrase:, file_enc:, file_out:, iterations:, salt: nil, base64:false)
      data = open(file_enc).read
      data = Base64.decode64(data) if base64
      data = data.force_encoding('ASCII-8bit')
      if salt.nil? || data.start_with?('Salted__') ## Salt 取り出し
        salt = data[8, 8]
        encrypted_data = data[16, data.size]
      else
        encrypted_data = data
      end

      cipher = OpenSSL::Cipher.new("AES-256-CBC")
      cipher.decrypt
      cipher.iv, cipher.key = pbkdf2_gen_key(passphrase, salt, iterations)

      decrypt_data = cipher.update(encrypted_data) + cipher.final
      open(file_out, 'wb') { |f| f.write decrypt_data }
      decrypt_data
    end

    def decrypt_by_openssl(passphrase:, file_in:, file_out:, iterations:, salt_str: nil, base64: false)
      ## ファイルからSalt取り出せるので nil でいい
      if salt_str.nil?
        `openssl enc -d -aes-256-cbc -pbkdf2 -iter #{iterations} -in #{file_in} -out #{file_out} -k #{passphrase} #{base64 ? '-base64' : ''}`
      elsif salt_str.is_a? String
        `openssl enc -d -aes-256-cbc -pbkdf2 -iter #{iterations} -S #{salt_str} -in #{file_in} -out #{file_out} -k #{passphrase} #{base64 ? '-base64' : ''}`
      end
    end

    def encrypt_by_openssl(passphrase:, file_in:, file_out:, iterations:, salt_str: nil, salted: false, base64: false)
      if salt_str.nil?
        `openssl enc -e -aes-256-cbc -pbkdf2 -iter #{iterations} -in #{file_in} -out #{file_out} -k #{passphrase} #{base64 ? '-base64' : ''}`
      else
        raise 'arg. :salted_str should be HEX.' unless salt_str && salt_str =~ /[0-9A-Fa-f]+/
        if !salted
          `openssl enc -e -aes-256-cbc -pbkdf2 -iter #{iterations} -S #{salt_str} -in #{file_in} -out #{file_out} -k #{passphrase} #{base64 ? '-base64' : ''}`
        else
          require 'tempfile'
          Tempfile.open do |tmp_f|
            encrypt_by_openssl(passphrase:, file_in:, file_out: tmp_f.path, iterations:, salt_str:)
            `(echo -n "Salted__"; echo #{salt_str} | xxd -r -p; cat #{tmp_f.path} ) #{base64 ? '| base64' : ''} > #{file_out}`
          end
        end
      end
    end

    def encrypt_by_openssl_salted(passphrase:, file_in:, file_out:, iterations:, salt_str:)
      require 'tempfile'
      Tempfile.open do |tmp_f|
        encrypt_by_openssl(passphrase:, file_in:, file_out: tmp_f.path, iterations:, salt_str:)
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