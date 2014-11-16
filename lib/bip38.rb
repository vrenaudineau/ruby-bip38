# -*- coding: utf-8 -*-

require 'openssl'
require 'digest'
require 'bitcoin'
require 'scrypt' # https://github.com/pbhogan/scrypt/blob/master/lib/scrypt.rb SCrypt::Engine.scrypt(secret, salt, n, r, p, key_len)
require 'unicode'
require "rqrcode"
require "mini_magick"

module Bip38
  VERSIONS = {
    private: 0x80,
    public: 0x0
  }
  # BIP38 recommended
  SCRYPT_PARAMS = {n: 16384, r: 8, p: 8}

  # Convert WIF to encrypted WIF
  def self.encrypt(wif, passphrase, address=nil)
    bin_pkey = Base58.decode58(wif)[1..-1]
    compressed = (bin_pkey.size === 33) && (bin_pkey[32] == 0x01)
    # truncate the compression flag
    bin_pkey = bin_pkey[0...-1] if compressed
    address = Bitcoin::Key.from_base58(wif).addr if address.nil?
    bin_enc_pkey = encrypt_raw(bin_pkey, compressed, passphrase, address)
    Base58.encode58( bin_enc_pkey )
  end

  # Convert encrypted WIF to WIF
  # If address is given, test with the corresponding decrypted pkey's address.
  def self.decrypt(encrypted_wif, passphrase, address=nil)
    bin_enc_pkey = Base58.decode58(encrypted_wif)
    bin_dec_pkey, compressed = decrypt_raw(bin_enc_pkey, passphrase)
    bin_pkey = [VERSIONS[:private], bin_dec_pkey].pack("CA*") # TODO: false
    bin_pkey.setbyte(33, 0x01) if compressed
    pkey = Base58.encode58( bin_pkey )
    if ! address.nil?
      pkey_address = Bitcoin::Key.from_base58(pkey).addr
      if pkey_address != address
        raise "Computed address #{pkey_address} != #{address}, the address given. Password MUST be wrong."
      end
    end
    return pkey
  end
    
  # string the string to encode
  # options:
  #   - size
  #   - level
  #   - format
  #   - filename
  #   - svg renderer options.
  # return aFile if filename is given, aImageStr otherwise
  def self.render_qrcode(string, options={})
    size   = options[:size]  || RQRCode.minimum_qr_size_from_string(string)
    level  = options[:level] || :h
    fname  = options[:filename]
    format = (fname && fname.match(/\.(\w+)$/) && $~[1]) || options[:format] || :svg

    qrcode = RQRCode::QRCode.new(string, :size => size, :level => level)
    svg    = RQRCode::Renderers::SVG::render(qrcode, options)

    if format == :svg
      image = svg
    else
      image = MiniMagick::Image.read(svg) { |i| i.format "svg" }
      image.format format
      image = image.to_blob
    end

    file = File.open(fname, "wb") { |f| f.write(image) } if fname
    file || image
  end

  def self.encrypt_raw(bin_pkey, compressed, passphrase, address)
    raise 'Invalid private key length' unless bin_pkey.size == 32
    salt = sha256x2(address)[0...4]
    # passphrase is encoded in UTF-8 and normalized using Unicode Normalization Form C (NFC)
    passphrase = Unicode::nfc(passphrase)
    n, r, p = *SCRYPT_PARAMS.values
    derived_half1, derived_half2 = *SCrypt::Engine.scrypt(passphrase, salt, n, r, p, 64).scan(/.{32}/)
    xorBuf = bufferXOR(bin_pkey, derived_half1)
    encrypted_half1 = aes(xorBuf[ 0...16], derived_half2, :encrypt)[0...16] # Take first 16 bytes
    encrypted_half2 = aes(xorBuf[16...32], derived_half2, :encrypt)[0...16] # Take first 16 bytes
    # 0x01 + 0x42 + flagByte + salt + encryptedHalf1 + encryptedHalf2
    prefix = [0x01, 0x42, compressed ? 0xe0 : 0xc0].pack("CCC")
    [prefix, salt, encrypted_half1, encrypted_half2].join
  end

	# some of the techniques borrowed from: https://github.com/pointbiz/bitaddress.org
	# todo: (optimization) init buffer in advance, and use copy instead of concat
  def self.decrypt_raw(bin_enc_pkey, passphrase)
  	# 39 bytes: 2 bytes prefix, 37 bytes payload
    raise 'Invalid BIP38 data length' unless bin_enc_pkey.size == 39
  	# first byte is always 0x01
    raise 'Invalid BIP38 prefix' unless bin_enc_pkey.getbyte(0) == 0x01

    # passphrase is encoded in UTF-8 and normalized using Unicode Normalization Form C (NFC)
    passphrase = Unicode::nfc(passphrase)

    # check if BIP38 EC multiply
    type = bin_enc_pkey.getbyte(1)
    return decrypt_ec_mult(bin_enc_pkey, passphrase) if type == 0x43
    
    raise 'Invalid BIP38 type' unless type == 0x42
    flag_byte = bin_enc_pkey.getbyte(2)
    compressed = flag_byte == 0xe0
    raise 'Invalid BIP38 compression flag' if ! compressed && flag_byte != 0xc0

    n, r, p = *SCRYPT_PARAMS.values
    addresshash = bin_enc_pkey[3...7]
    derived_half1, derived_half2 = SCrypt::Engine.scrypt(passphrase, addresshash, n, r, p, 64).scan(/.{32}/)

    bin_pkey = bin_enc_pkey[7...7+32]
    decrypted_half1 = aes(bin_pkey[ 0...16], derived_half2, :decrypt)[0...16] # Take first 16 bytes
    decrypted_half2 = aes(bin_pkey[16...32], derived_half2, :decrypt)[0...16] # Take first 16 bytes
    decrypted = decrypted_half1 + decrypted_half2
    bin_dec_pkey = bufferXOR( decrypted, derived_half1 )
    return bin_dec_pkey, compressed
  end

  def self.bufferXOR(buf1, buf2)
    raise 'buffers must be same size' unless buf1.size == buf2.size
    buf1.bytesize.times.map { |i| buf1.getbyte(i) ^ buf2.getbyte(i) }.map(&:chr).join
  end

  def self.aes(data, key, method)
    cipher = OpenSSL::Cipher::AES256.new('ECB')
    cipher.encrypt if method == :encrypt
    cipher.decrypt if method == :decrypt
    cipher.padding = 0
    cipher.key = key
    cipher.update(data) + cipher.final
  end

  def self.sha256x2(bin_buffer)
    Digest::SHA256.digest(Digest::SHA256.digest(bin_buffer))
  end
  
  def self.decrypt_ec_mult(encData, passphrase)
    raise 'Not supported yet.'
#     passphrase = String.new(passphrase, 'utf8')
#     encData = encData.slice(1) # FIXME: we can avoid this

#     compressed = (encData[1] & 0x20) != 0
#     hasLotSeq = (encData[1] & 0x04) != 0

#     raise "Invalid private key." unless (encData[1] & 0x24) == encData[1]

#     addresshash = encData[2...6]
#     ownerEntropy = encData[6...14]
    
#     # 4 bytes ownerSalt if 4 bytes lot/sequence
#     # else, 8 bytes ownerSalt
#     ownerSalt = hasLotSeq ? ownerEntropy[0...4] : ownerEntropy

#     encryptedPart1 = encData[14...22] # First 8 bytes
#     encryptedPart2 = encData[22...38] # 16 bytes

#     n = @scryptParams[:n]
#     r = @scryptParams[:r]
#     p = @scryptParams[:p]
#     preFactor = scrypt(passphrase, ownerSalt, n, r, p, 32)
#     passFactor = hasLotSeq ? sha256x2([preFactor, ownerEntropy].join) : preFactor
#     passInt = BigInteger.fromBuffer(passFactor)
#     passPoint = curve.G.multiply(passInt).getEncoded(true)

#     seedBPass = scrypt(passPoint, Buffer.concat([addresshash, ownerEntropy]), 1024, 1, 1, 64)
#     derivedHalf1 = seedBPass[0...32]
#     derivedHalf2 = seedBPass[32...64]

#     aes = createAES(derivedHalf2)
#     decryptFn = aes.decrypt.bind(aes)

#     tmp = bufferXOR(callAES(encryptedPart2, decryptFn), derivedHalf1[16...32])
#     encryptedPart1 = Buffer.concat([encryptedPart1, tmp[0... 8]], 16); # Append last 8 bytes

#     seedBPart2 = tmp[8...16]
#     tmp2 = callAES(encryptedPart1, decryptFn)
#     seedBPart1 = bufferXOR(tmp2, derivedHalf1[0...16])
#     seedB = Buffer.concat([seedBPart1, seedBPart2], 24)
#     factorB = sha256x2(seedB)

#     # d = passFactor * factorB (mod n)
#     d = passInt.multiply(BigInteger.fromBuffer(factorB)).mod(curve.n)

#     return d.toBuffer(), compressed]
  end

  ADDRESS = '1Jq6MksXQVWzrznvZzxkV6oY57oWXD9TXB'
  WIF = "5KN7MzqK5wt2TP1fQCYyHBtDrXdJuXbUzm4A9rKAteGu3Qi5CVR"
  PASSPHRASE = "TestingOneTwoThree"
  ENCRYPTED = "6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg"
end

module Base58
  # if payload is ascii-8bit encoding, we assume it is a binary String,
  # otherwise it is a hex encoding String.
  def self.encode58(payload)
    if payload.encoding != Encoding::ASCII_8BIT && payload =~ /^([a-fA-F0-9][a-fA-F0-9])+$/
      payload = [payload].pack('H*')
    end
    checksum = sha256x2(payload)[0...4]
    result = payload + checksum
    return Bitcoin.encode_base58(result.unpack('H*')[0])
  end

  def self.decode58(base58str)
    hex_buf = Bitcoin.decode_base58(base58str)
    bin_buf = [hex_buf].pack('H*')

    bytes, checksum = bin_buf[0...-4], bin_buf[-4..-1]

    newChecksum = sha256x2(bytes)[0...4]
    raise 'Invalid checksum' if checksum != newChecksum
    return bytes
  end

  def self.sha256x2(buffer)
    Digest::SHA256.digest(Digest::SHA256.digest(buffer))
  end
end

module Base16
  def self.enc(str)
    str.unpack('H*')[0]
  end
  def self.dec(str)
    [str].pack('H*')
  end
end
B16 = Base16

module Base6
  def self.dec(str)
    nb = str.reverse.split('').map(&:to_i).each_with_index.map do |n,i| n * 6**i end.inject(:+)
    s = "%x" % nb
    s = '0' + s if s.size.odd?
    [s].pack('H*')
  end  
end

# Code from https://github.com/samvincent/rqrcode-rails3
module RQRCode
  # size - seems to follow this logic
  #     # | input | modules 
  #       | size  | created
  #-------|-------|--------
  #     1 |     7 |      21
  #     2 |    14 |      25 (+4)
  #     3 |    24 |      29   -
  #     4 |    34 |      33   -
  #     5 |    44 |      37   -
  #     6 |    58 |      41   -
  #     7 |    64 |      45   -
  #     8 |    84 |      49   -
  #     9 |    98 |      53   -
  #    10 |   119 |      57   -
  #    11 |   137 |      61   -
  #    12 |   155 |      65   -
  #    13 |   177 |      69   -
  #    14 |   194 |      73   -
  
  QR_CHAR_SIZE_VS_SIZE = [7, 14, 24, 34, 44, 58, 64, 84, 98, 119, 137, 155, 177, 194]
  
  def self.minimum_qr_size_from_string(string)
    QR_CHAR_SIZE_VS_SIZE.each_with_index do |size, index|
      return (index + 1) if string.size < size
    end
    
    # If it's particularly big, we'll try and create codes until it accepts
    i = QR_CHAR_SIZE_VS_SIZE.size
    begin
      i += 1
      RQRCode::QRCode.new(string, :size => i)
      return i
    rescue RQRCode::QRCodeRunTimeError
      retry
    end
  end

  module Renderers
    class SVG
      class << self
        # Render the SVG from the qrcode string provided from the RQRCode gem
        #   Options:
        #   offset - Padding around the QR Code (e.g. 10)
        #   unit   - How many pixels per module (Default: 11)
        #   fill   - Background color (e.g "ffffff" or :white)
        #   color  - Foreground color for the code (e.g. "000000" or :black)

        def render(qrcode, options={})
          offset  = options[:offset].to_i || 0
          color   = options[:color]       || "000"
          unit    = options[:unit]        || 11

          # height and width dependent on offset and QR complexity
          dimension = (qrcode.module_count*unit) + (2*offset)

          xml_tag   = %{<?xml version="1.0" standalone="yes"?>}
          open_tag  = %{<svg version="1.1" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" xmlns:ev="http://www.w3.org/2001/xml-events" width="#{dimension}" height="#{dimension}">}
          close_tag = "</svg>"

          result = []
          qrcode.modules.each_index do |c|
            tmp = []
            qrcode.modules.each_index do |r|
              y = c*unit + offset
              x = r*unit + offset

              next unless qrcode.is_dark(c, r)
              tmp << %{<rect width="#{unit}" height="#{unit}" x="#{x}" y="#{y}" style="fill:##{color}"/>}
            end 
            result << tmp.join
          end
          
          if options[:fill]
            result.unshift %{<rect width="#{dimension}" height="#{dimension}" x="0" y="0" style="fill:##{options[:fill]}"/>}
          end
          
          svg = [xml_tag, open_tag, result, close_tag].flatten.join("\n")
        end
      end
    end
  end
end