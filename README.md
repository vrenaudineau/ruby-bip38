bip38
=====

A Ruby implementation of the BIP-0038 draft for encryption of Bitcoin keys

Usage
-----

    require "bip38"

    wif = "5J436hag3QHz2Eb4iGc9jxT2mcmWnPp1TzCxJQzyrSxjA669PXX"
    address = "1bipG8QikR6J3RcomPLbkmxn18p18SAWb"
    password = "password0123"

    encrypted_wif = Bip38.encrypt(wif, password)
    # => "6PRMuyqDdnzcLwtk7M2yBh4qCEn3XXT8wQpb7Qpqcj97AV9Ci77TPsMtXR"

    Bip38.decrypt(encrypted_wif, password)
    # => "5J436hag3QHz2Eb4iGc9jxT2mcmWnPp1TzCxJQzyrSxjA669PXX"

TODO
----

End to implement the spec :
- Unicode normalizing the password
- Compression flag
- Multiply flag
