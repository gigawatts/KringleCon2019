require 'openssl'
require 'base64'

KEY_LENGTH = 8

def generate_key(seed)
  key = ""
  1.upto(KEY_LENGTH) do
    key += ((seed = (214013 * seed + 2531011) & 0x7fff_ffff ) >> 16 & 0x0FF).chr
  end
  return key
end

def decrypt_file(key, enc_file, dec_file)
  cipher = OpenSSL::Cipher::new('DES-CBC')
  cipher.padding = 0
  cipher.key = key
  b64_iv = "AAAAAAAAAAA="
  cipher.iv = Base64.decode64(b64_iv)
  File.open(dec_file, 'wb') do |outf|
    decrypted = cipher.update(File.read(enc_file)) + cipher.final
    outf.write(decrypted)
  end
end

if(!ARGV[1])
    puts("Usage: ruby ./solve.rb <seed> <encrypted input file>")
    exit
end

seed = ARGV[0].to_i
enc_file = ARGV[1]
dec_file = "out/#{seed}-dec.pdf"

puts("Input Seed: #{seed}")

key = generate_key(seed)
puts("Generated key: #{key.unpack('H*')}")

decrypt_file(key, enc_file, dec_file)
puts "Decrypted file -> #{dec_file}"
