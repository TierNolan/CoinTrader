from __future__ import absolute_import, division, print_function, unicode_literals

import binascii
import hashlib

symbols = u'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
reverse_map = {}

i = 0
for symbol in symbols:
    reverse_map[symbol] = i
    i += 1


def double_hash(data):
    hash1 = hashlib.sha256(data).digest()
    hash2 = hashlib.sha256(hash1).digest()
    return hash2


def encode(bin_string, version=b'', crc=True):

    if crc:
        hash_crc = double_hash(bin_string + version)
        bin_string += hash_crc[0:4]

    hex_string = binascii.hexlify(bin_string)
    i = 0
    while i < len(hex_string) and hex_string[i:i+2] == u'00':
        i += 2

    zeros = i // 2

    if hex_string == u'':
        value = 0
    else:
        value = int(hex_string, 16)

    encoded = u''

    while value > 0:
        value, sym = divmod(value, 58)
        encoded = symbols[sym] + encoded

    encoded = u'1' * zeros + encoded

    return encoded


def decode(encoded, version=None, crc=True):

    zeros = 0
    while zeros < len(encoded) and encoded[zeros] == u'1':
        zeros += 1

    encoded = encoded[zeros:]

    value = 0

    for symbol in encoded:
        code = reverse_map[symbol]
        value *= 58
        value += code

    if value == 0:
        hex = u''
    else:
        hex = u'%x' % value

    if len(hex) % 2 == 1:
        hex = u'0' + hex

    hex = u'00' * zeros + hex

    if version:
        if hex[0:2] != version:
            raise ValueError("Version does not match")
        hex = hex[2:]

    bin_string = binascii.unhexlify(hex)

    if crc:
        hash_crc = double_hash(bin_string[:-4])
        if hash_crc[0:4] != bin_string[-4:]:
            raise ValueError("CRC mismatch")
        return bin_string[:-4]

    return bin_string

if __name__ == '__main__':

    try:
        tests = [
            ["", ""],
            ["61", "2g"],
            ["626262", "a3gV"],
            ["636363", "aPEr"],
            ["73696d706c792061206c6f6e6720737472696e67", "2cFupjhnEsSn59qHXstmK2ffpLv2"],
            ["00eb15231dfceb60925886b67d065299925915aeb172c06647", "1NS17iag9jJgTHD1VXjvLCEnZuQ3rJDE9L"],
            ["516b6fcd0f", "ABnLTmg"],
            ["bf4f89001e670274dd", "3SEo3LWLoPntC"],
            ["572e4794", "3EFU7m"],
            ["ecac89cad93923c02321", "EJDM8drfXA6uyA"],
            ["10c8511e", "Rt5zm"],
            ["00000000000000000000", "1111111111"]
        ]

        for test in tests:
            data = binascii.unhexlify(test[0])
            encoded = test[1]
            if encoded != encode(data, crc=False):
                raise ValueError('Base58 encoded test mismatch')
            if data != decode(encoded, crc=False):
                raise ValueError('Base58 decode test mismatch')

        decode('93N87D6uxSBzwXvpokpzg8FFmfQPmvX4xHoWQe3pLdYpbiwT5YV', crc=True)
    except ValueError:
        print ("Tests failed")
