## openssl enc equivalent in ruby

This repository has sample function encryption ( decrypt / ecrypt ) equivalent of `openssl enc` command output.

## Samples, openssl enc

left side is encryption , right side is decryption.
```shell
## 
openssl enc -e -S $RAND -pbkdf2 -iter $i -base64  -in - -out -  | \
openssl enc -d -S $RAND -pbkdf2 -iter $i -base64  -in - -out - 
```

| sample | encrypt:<br/>-S opt | enc:base64 | output |   __Salted   | decrypt:<br/> -S opt | dec:base64 |
|:------:|--------------------:|-----------:|:------:|:------------:|---------------------:|-----------:|
|   01   |                none |       none | binary |     YES      |                 none |       none |
|   02   |            -S $RAND |       none | binary |      NO      |             -S $RAND |       none |
|   03   |                none |    -base64 | BASE64 |     YES      |                 none |    -base64 |
|   04   |            -S $RAND |    -base64 | BASE64 |      NO      |             -S $RAND |    -base64 |
|   05   |            -S $RAND |    -base64 | BASE64 | **manually** |                 none |    -base64 |
|   06   |            -S $RAND |       none | binary | **manually** |             -S $RAND |       none |

`$RAND` is random 8bytes. `RAND=$(openssl rand -hex 8  )`

`__Salted` prefixed in encrypted file, openssl can decrypt without`  -S `, because $RAND is included $RAND as "Salted__$RAND" , but same `-iter cnt` will be needed.

**manually** means, adding `SALTED__` by command , not by `openssl enc`, such as echo cat command, for example `(echo -n "Salted__"; echo -n "${rand}" | xxd -r -p; cat ${file_tmp} ) | base64 -w 64 > "${file_out}"`

`iter` is to prevent brute force attack. iter count should be increased over than 1sec to calculating , for attacker time consuming.(ex 1000*1000)

## 01 . shell command `openssl enc`, simple encryption.

```shell
## params
i=$(( 1000* 1000 ))
file_in=/etc/resolv.conf
file_out=/tmp/file.enc
passphrase="my_strong_password"


## encryption
openssl enc -e -aes-256-cbc \
  -pbkdf2 -iter "${i}" \
  -in "${file_in}" -out "${file_out}" \
  -k "${passphrase}"

## decryption
enc_file=${file_out}
output='-'
openssl enc -d -aes-256-cbc \
  -pbkdf2 -iter "${i}" \
  -in "${enc_file}" -out "${output}" \
  -k "${passphrase}"

```

## 02.shell command `openssl enc` , simple encryption with SALT specified.

```shell
## params
i=$(( 1000* 1000 ))
file_in=/etc/resolv.conf
file_out=/tmp/file.enc
passphrase="my_strong_password"
rand=$(openssl rand -hex 8  ) ## with 8 bytes 

## encryption
openssl enc -e -aes-256-cbc \
  -pbkdf2 -iter "${i}" -S "${rand}" \
  -in "${file_in}" -out "${file_out}" \
  -k "${passphrase}"
  
## decryption
enc_file=${file_out}
output='-'
openssl enc -d -aes-256-cbc \
  -pbkdf2 -iter "${i}" \
  -S "${rand}" \
  -in "${enc_file}" -out "${output}" \
  -k "${passphrase}"
```

## 03.shell command base64 and salted by `openssl enc ` and BASE 64.

```shell
## params
i=$(( 1000* 1000 ))
file_in=/etc/resolv.conf
file_out=/tmp/file.enc
rand=$(openssl rand -hex 8  )
passphrase="my_strong_password"

## encryption 
openssl enc -e -aes-256-cbc \
  -pbkdf2 -iter "${i}" \
  -in "${file_in}" -out "${file_out}" \
  -k "${passphrase}"\
  -base64 \
  ;
## decryption
enc_file=${file_out}
output='-'
openssl enc -d -aes-256-cbc \
  -pbkdf2 -iter "${i}" \
  -in "${enc_file}" -out "${output}" \
  -k "${passphrase}" \
  -base64 \
  ;
```

## 04. shell command encrypt / decrypt BASE64.

```shell
## params
i=$(( 1000* 1000 ))
file_in=/etc/resolv.conf
file_out=/tmp/file.enc
rand=$(openssl rand -hex 8  )
passphrase="my_strong_password"

## encryption no salted.
openssl enc -e -aes-256-cbc \
  -pbkdf2 -iter "${i}" \
  -in "${file_in}" -out "${file_out}" \
  -k "${passphrase}"\
  -S "${rand}" \
  -base64 \
;  
## decrypt
enc_file=${file_out}
output='-'
openssl enc -d -aes-256-cbc \
  -pbkdf2 -iter "${i}" \
  -in ${enc_file} -out ${output} \
  -k "${passphrase}" \
  -S "${rand}" \
  -base64 \
;
```

## 05.shell command manually add "Salted__" and BASE 64 .

manually salted.

```shell
## params
i=$(( 1000* 1000 ))
file_in=/etc/resolv.conf
file_out=/tmp/file.enc
rand=$(openssl rand -hex 8  )
passphrase="my_strong_password"

## encryption ( with -S -base64 ) will not output "Salted__"
file_tmp=$(mktemp -u)
  openssl enc -e -aes-256-cbc \
  -pbkdf2 -iter "${i}" \
  -in "${file_in}" -out "${file_tmp}" \
  -k "${passphrase}"\
  -S "${rand}" \
  ;
(echo -n "Salted__"; echo -n "${rand}" | xxd -r -p; cat ${file_tmp} ) | base64 -w 64 > "${file_out}" 

## decrypt 
enc_file=${file_out}
output='-'
openssl enc -d -aes-256-cbc \
  -pbkdf2 -iter "${i}" \
  -in ${enc_file} -out ${output} \
  -k "${passphrase}" \
  -base64 \
  ;
```

## ruby sample 
```ruby
require_relative '../lib/openssl/utils' # this repository.

file = 'my.txt'
enc_file = 'my.enc'
out_file = 'my.out'
pass = 'your_password_here'
salt_str = `openssl rand -hex 8`.strip
salt = [salt_str].pack('H*') # HEX dump
iter_cnt = 1000 * 10

## encryption with salted__ , base64 . #05
OpenSSLEncryption.encrypt_by_ruby(passphrase: pass, file_in: file, file_out: enc_file, iterations: iter_cnt, salt: salt, salted: false,base64: true)
## decryption by openssl command (wrapper)
OpenSSLEncryption.decrypt_by_openssl(passphrase: pass, file_in: enc_file, file_out: out_file, iterations: iter_cnt, salt_str: salt_str,base64: true)
```

## notice 

openssl command cannot accept salt as 'binary'. Command line `SALT` must be `HEX` string.


