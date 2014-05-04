from __future__ import absolute_import, division, print_function, unicode_literals

import ecdsa
import ecdsa.curves
import bitcoin
import binascii


class ChainTrader(object):

    def __init__(self, fast_trader,
                 fast_rpc_interface, fast_value, fast_fee,
                 slow_rpc_interface, slow_value, slow_fee):

        self.__fast_trader = fast_trader

        self.__fast_rpc_interface = fast_rpc_interface
        self.__fast_value = fast_value
        self.__fast_fee = fast_fee

        self.__slow_rpc_interface = slow_rpc_interface
        self.__slow_value = slow_value
        self.__slow_fee = slow_fee

        self.__fast_public_keys = None
        self.__fast_private_keys = None

        self.__slow_public_keys = None
        self.__slow_private_keys = None

        self.__fast_bail_in_hash = None
        self.__slow_bail_in_hash = None

        self.__bail_in_redeem = None

        self.__x = None
        self.__hash160_x = None

    def __generate_keys(self):
        i = 0
        public_keys = []
        private_keys = []
        while i < 6:
            key_private = ecdsa.SigningKey.generate(ecdsa.curves.SECP256k1)
            key_der = self.__fast_rpc_interface.get_der_key_from_ecdsa_key(key_private)

            private_keys.append(key_private)
            public_keys.append(key_der)
            i += 1

        return private_keys, public_keys

    def set_fast_keys(self, keys):
        if len(keys) != 6:
            raise ValueError("6 keys must be provided")
        self.__fast_public_keys = keys

    def generate_fast_keys(self):
        keys = self.__generate_keys()
        self.set_fast_keys(keys[1])
        self.__fast_private_keys = keys[0]

    def get_fast_public_keys(self):
        return self.__fast_public_keys

    def set_slow_keys(self, keys):
        if len(keys) != 6:
            raise ValueError("6 keys must be provided")
        self.__slow_public_keys = keys

    def generate_slow_keys(self):
        keys = self.__generate_keys()
        self.set_slow_keys(keys[1])
        self.__slow_private_keys = keys[0]

    def get_slow_public_keys(self):
        return self.__slow_public_keys

    def generate_hash_x(self):
        if self.__fast_trader:
            raise ValueError("Fast trader must not generate hash_x")
        self.__x = self.__slow_rpc_interface.get_pay_to_pub_key_script_pub_key(self.__slow_public_keys[5])
        self.__hash160_x = bitcoin.Hash160(binascii.unhexlify(self.__x)).hexdigest()

    def set_hash_x(self, hash160_x):
        if not self.__fast_trader:
            raise ValueError("Slow trader must generate x from P2SH script")
        self.__hash160_x = hash160_x

    def generate_bail_in_transaction(self):
        if self.__fast_trader:
            rpc_interface = self.__fast_rpc_interface
            payout = self.__fast_value + 2 * self.__fast_fee
            pub_keys = self.__fast_public_keys
        else:
            rpc_interface = self.__slow_rpc_interface
            payout = self.__slow_value + 2 * self.__slow_fee
            pub_keys = self.__slow_public_keys

        self.__bail_in_redeem = \
            bitcoin.OP_HASH160() + \
            bitcoin.OP_N(2) + \
            bitcoin.OP_PUSH(self.__fast_public_keys[0]) + \
            bitcoin.OP_PUSH(self.__slow_public_keys[0]) + \
            bitcoin.OP_N(2) + \
            bitcoin.OP_CHECKMULTISIG()

        hash_redeem = bitcoin.Hash160(binascii.unhexlify(self.__bail_in_redeem)).hexdigest()

        output_0_script_pub_key = \
            bitcoin.OP_HASH160() + \
            bitcoin.OP_PUSH(hash_redeem) + \
            bitcoin.OP_EQUAL()

        if self.__fast_trader:
            output_1_script_pub_key = \
                bitcoin.OP_HASH160() + \
                bitcoin.OP_PUSH(self.__hash160_x) + \
                bitcoin.OP_EQUAL_VERIFY() + \
                bitcoin.OP_PUSH(self.__fast_public_keys[0]) + \
                bitcoin.OP_CHECKSIG()
        else:
            output_1_script_pub_key = \
                bitcoin.OP_HASH160() + \
                bitcoin.OP_PUSH(self.__hash160_x) + \
                bitcoin.OP_EQUAL()

    def generate_transactions(self):
        if not self.__fast_public_keys:
            raise ValueError("Missing fast key set")
        elif not self.__slow_public_keys:
            raise ValueError("Missing slow key set")
        elif not self.__fast_bail_in_hash:
            raise ValueError("Unknown fast bail-in hash")
        elif not self.__slow_bail_in_hash:
            raise ValueError("Unknown slow bail-in hash")
