from __future__ import absolute_import, division, print_function, unicode_literals

import ecdsa
import ecdsa.curves
import bitcoin
import binascii
import base58

KEY_COUNT = 4


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

        self.__fast_bail_in_transaction = None
        self.__slow_bail_in_transaction = None

        self.__fast_bail_in_hash = None
        self.__slow_bail_in_hash = None

        self.__fast_payout_transaction = None
        self.__slow_payout_transaction = None

        self.__fast_payout_redeem = None
        self.__slow_payout_redeem = None

        self.__bail_in_redeem = None

        self.__x = None
        self.__hash160_x = None

        self.__slow_bail_in_script_1 = None

        self.__sig_fast_payout_0 = None
        self.__sig_fast_payout_1 = None

        self.__sig_slow_payout_0 = None
        self.__sig_slow_payout_1 = None

    def _force_bail_in_hashes(self, fast_bail_in_hash, slow_bail_in_hash):
        self.__fast_bail_in_hash = fast_bail_in_hash
        self.__slow_bail_in_hash = slow_bail_in_hash

    def get_bail_in_hash(self):
        if self.__fast_trader:
            return self.__fast_bail_in_hash
        else:
            return self.__slow_bail_in_hash

    def set_bail_in_hash(self, bail_in_hash):
        if self.__fast_trader:
            self.__slow_bail_in_hash = bail_in_hash
        else:
            self.__fast_bail_in_hash = bail_in_hash

    def __generate_keys(self, secexp=None):
        i = 0
        public_keys = []
        private_keys = []
        while i < KEY_COUNT:
            if secexp:
                key_private = ecdsa.SigningKey.from_secret_exponent(i + secexp, ecdsa.curves.SECP256k1)
            else:
                # key_private = ecdsa.SigningKey.generate(ecdsa.curves.SECP256k1)
                key_private = self.__fast_rpc_interface.get_private_key()

            key_der = self.__fast_rpc_interface.get_der_key_from_ecdsa_key(key_private)

            private_keys.append(key_private)
            public_keys.append(key_der)
            i += 1

        return private_keys, public_keys

    def generate_fast_keys(self, secexp=None):
        keys = self.__generate_keys(secexp)
        self.set_fast_keys(keys[1])
        self.__fast_private_keys = keys[0]

    def generate_slow_keys(self, secexp=None):
        keys = self.__generate_keys(secexp)
        self.set_slow_keys(keys[1])
        self.__slow_private_keys = keys[0]

    def generate_keys(self, secexp=None):
        if self.__fast_trader:
            self.generate_fast_keys(secexp)
        else:
            self.generate_slow_keys(secexp)

    def get_fast_public_keys(self):
        return self.__fast_public_keys

    def get_slow_public_keys(self):
        return self.__slow_public_keys

    def get_public_keys(self):
        if self.__fast_trader:
            return self.get_fast_public_keys()
        else:
            return self.get_slow_public_keys()

    def set_fast_keys(self, keys):
        if len(keys) != KEY_COUNT:
            raise ValueError("%d keys must be provided" % KEY_COUNT)
        self.__fast_public_keys = keys

    def set_slow_keys(self, keys):
        if len(keys) != KEY_COUNT:
            raise ValueError("%d keys must be provided" % KEY_COUNT)
        self.__slow_public_keys = keys

    def set_keys(self, keys):
        if self.__fast_trader:
            self.set_slow_keys(keys)
        else:
            self.set_fast_keys(keys)

    def generate_hash_x(self):
        if self.__fast_trader:
            raise ValueError("Fast trader must not generate hash_x")

        self.__x = self.__slow_rpc_interface.get_pay_to_pub_key_script_pub_key(self.__slow_public_keys[3])
        self.__hash160_x = bitcoin.Hash160(binascii.unhexlify(self.__x)).hexdigest()

        return self.__hash160_x

    def set_hash_x(self, hash160_x):
        if not self.__fast_trader:
            raise ValueError("Slow trader must generate x from P2SH script")
        self.__hash160_x = hash160_x

    def set_x(self, x):
        if not self.__fast_trader:
            raise ValueError("Only the fast trader receives x")
        self.__x = x
        if bitcoin.Hash160(binascii.unhexlify(self.__x)).hexdigest() != self.__hash160_x:
            raise ValueError("Hash160(x) does not match the expected value")

    def generate_bail_in_transaction(self, server_sign=True):

        if self.__fast_trader:
            rpc_interface = self.__fast_rpc_interface
            payout_value = self.__fast_value
            payout_fee = self.__fast_fee
        else:
            rpc_interface = self.__slow_rpc_interface
            payout_value = self.__slow_value
            payout_fee = self.__slow_fee

        self.__bail_in_redeem = \
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

        self.__slow_bail_in_script_1 = \
            bitcoin.OP_HASH160() + \
            bitcoin.OP_PUSH(self.__hash160_x) + \
            bitcoin.OP_EQUAL_VERIFY() + \
            bitcoin.OP_PUSH(self.__fast_public_keys[0]) + \
            bitcoin.OP_CHECKSIG()

        if self.__fast_trader:
            output_1_script_pub_key = \
                bitcoin.OP_HASH160() + \
                bitcoin.OP_PUSH(self.__hash160_x) + \
                bitcoin.OP_EQUAL()
        else:
            output_1_script_pub_key = self.__slow_bail_in_script_1

        output_0 = (output_0_script_pub_key, payout_value)
        output_1 = (output_1_script_pub_key, payout_fee)

        if server_sign:
            bail_in_tx = rpc_interface.create_pay_to([output_0, output_1], payout_fee, True)
            if not bail_in_tx:
                raise ValueError("Insufficient coins to proceed")
            signed_bail_in_tx = rpc_interface.sign_transaction_by_server(bail_in_tx)
        else:
            signed_bail_in_tx = u''

        if self.__fast_trader:
            self.__fast_bail_in_transaction = signed_bail_in_tx
            self.__fast_bail_in_hash = bitcoin.DoubleSHA256(binascii.unhexlify(signed_bail_in_tx)).hexdigest()
        else:
            self.__slow_bail_in_transaction = signed_bail_in_tx
            self.__slow_bail_in_hash = bitcoin.DoubleSHA256(binascii.unhexlify(signed_bail_in_tx)).hexdigest()

        return signed_bail_in_tx

    def generate_transactions(self):
        if not self.__fast_public_keys:
            raise ValueError("Missing fast key set")
        elif not self.__slow_public_keys:
            raise ValueError("Missing slow key set")
        elif not self.__fast_bail_in_hash:
            raise ValueError("Unknown fast bail-in hash")
        elif not self.__slow_bail_in_hash:
            raise ValueError("Unknown slow bail-in hash")

        fast_input0 = (self.__fast_bail_in_hash, 0)
        fast_input1 = (self.__fast_bail_in_hash, 1)

        slow_input0 = (self.__slow_bail_in_hash, 0)
        slow_input1 = (self.__slow_bail_in_hash, 1)

        self.__fast_payout_redeem = bitcoin.OP_PUSH(self.__fast_public_keys[1]) + bitcoin.OP_CHECKSIG()
        self.__slow_payout_redeem = bitcoin.OP_PUSH(self.__slow_public_keys[1]) + bitcoin.OP_CHECKSIG()

        self.__slow_payout_transaction = self.__fast_rpc_interface.create_raw_transaction(
            [fast_input0, fast_input1], [(self.__slow_payout_redeem, self.__fast_value)])

        self.__fast_payout_transaction = self.__fast_rpc_interface.create_raw_transaction(
            [slow_input0, slow_input1], [(self.__fast_payout_redeem, self.__slow_value)])

    def sign_transactions(self):
        if self.__fast_trader:
            private_keys = self.__fast_private_keys
        else:
            private_keys = self.__slow_private_keys

        self.__sig_fast_payout_0 = self.__fast_rpc_interface.sign_transaction_input(self.__fast_payout_transaction,
                                                                                    self.__bail_in_redeem, 0,
                                                                                    private_keys[0])

        self.__sig_slow_payout_0 = self.__slow_rpc_interface.sign_transaction_input(self.__slow_payout_transaction,
                                                                                    self.__bail_in_redeem, 0,
                                                                                    private_keys[0])

        if self.__fast_trader:
            self.__sig_fast_payout_1 = self.__fast_rpc_interface.sign_transaction_input(self.__fast_payout_transaction,
                                                                                        self.__slow_bail_in_script_1, 1,
                                                                                        private_keys[0])
        else:
            self.__sig_slow_payout_1 = self.__slow_rpc_interface.sign_transaction_input(self.__slow_payout_transaction,
                                                                                        self.__x, 1,
                                                                                        private_keys[3])

        if self.__fast_trader:
            return [self.__sig_slow_payout_0]
        else:
            return [self.__sig_fast_payout_0]

    def send_payout(self, other_party_signatures, ):

        if self.__fast_trader:
            self.__sig_slow_payout_0 = other_party_signatures[0]
        else:
            self.__sig_fast_payout_0 = other_party_signatures[0]

        payout_sigs_0 = [bitcoin.OP_N(0), self.__sig_fast_payout_0, self.__sig_slow_payout_0, self.__bail_in_redeem]

        if self.__fast_trader:
            payout_sigs_1 = [self.__sig_fast_payout_1, self.__x]

            payout_tx = self.__fast_payout_transaction
        else:
            payout_sigs_1 = [self.__sig_slow_payout_1, self.__x]

            payout_tx = self.__slow_payout_transaction

        payout_tx_sig = self.__slow_rpc_interface.add_signatures_to_raw_transaction(payout_tx, 0, payout_sigs_0)
        payout_tx_sig = self.__slow_rpc_interface.add_signatures_to_raw_transaction(payout_tx_sig, 1, payout_sigs_1)

        if self.__fast_trader:
            self.__slow_rpc_interface.send_raw_transaction(payout_tx_sig)
        else:
            self.__fast_rpc_interface.send_raw_transaction(payout_tx_sig)

        return self.__x