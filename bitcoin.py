from __future__ import absolute_import, division, print_function, unicode_literals

import authproxy
import binascii
import hashlib
import base58
import ecdsa

VARINT_LIMIT = 0xFD


def OP_PUSH(x):
    l = len(x)
    if l % 2 != 0:
        raise Exception
    l //= 2
    if l > 75 or l <= 0:
        raise Exception
    return u'%02x%s' % (l, x)


def OP_N(x):
    if 0 <= x <= 16:
        if x == 0:
            return u'00'
        else:
            return u'%02x' % (x + 0x50)
    else:
        raise ValueError("OP_N out of range [0 to 16]")


def OP_EQUAL():
        return u'87'


def OP_EQUAL_VERIFY():
    return u'88'


def OP_HASH160():
    return u'a9'


def OP_CHECKSIG():
    return u'ac'


def OP_CHECKMULTISIG():
    return u'ae'


class DoubleSHA256(object):
    """ Class to perform double SHA256"""
    digest_size = 32

    block_size = 64

    def __init__(self, *args):
        self.__hash_obj = hashlib.sha256(*args)

    def update(self, message):
        self.__hash_obj.update(message)

    def digest(self):
        hash2 = hashlib.sha256(self.__hash_obj.digest()).digest()
        return hash2

    def hexdigest(self):
        return binascii.hexlify(self.digest())

    def copy(self):
        new_hash = DoubleSHA256()
        new_hash.__hash_obj = self.__hash_obj.copy()
        return new_hash


class Hash160(object):
    """ Class to perform SHA256 thane RIPEMD160"""
    digest_size = 32

    block_size = 64

    def __init__(self, *args):
        self.__hash_obj = hashlib.sha256(*args)

    def update(self, message):
        self.__hash_obj.update(message)

    def digest(self):
        ripemd = hashlib.new('ripemd160')
        ripemd.update(self.__hash_obj.digest())
        hash2 = ripemd.digest()
        return hash2

    def hexdigest(self):
        return binascii.hexlify(self.digest())

    def copy(self):
        new_hash = DoubleSHA256()
        new_hash.__hash_obj = self.__hash_obj.copy()
        return new_hash


class RPCInterface(object):

    def __init__(self, service_url, amount_multiplier):
        self.__rpc = authproxy.AuthServiceProxy(service_url)
        self.__amount_multiplier = amount_multiplier

    def hex_swap(self, hex_str):
        """Coverts a hex encoded byte array between big and little endian"""

        hex_str = hex_str.strip()

        if len(hex_str) % 2 != 0:
            raise Exception

        i = len(hex_str) - 2
        new_hex = u''

        while i >= 0:
            new_hex += hex_str[i:i+2]
            i -= 2

        return new_hex

    def lockunspent(self, txid, index):
        return self.__rpc.lockunspent(False, [{"txid": self.hex_swap(txid), "vout":index}])

    def unlock_all_unspent(self):
        self.__rpc.lockunspent(True)

    def get_inputs_hex_from_out_points(self, out_points):
        """
        Gets the hex encoded inputs section of a transaction
        :param outputs: array of out_point tuples
                        (txout_hash, txout_index) or
                        (txout_hash, txout_index, txin_sequence)
        :return: hex encoded input section of the transaction
        """

        if len(out_points) >= VARINT_LIMIT:
            raise ValueError("Number of inputs exceeded maximum supported %d >= %d", (len(out_points), VARINT_LIMIT))

        input_hex = u'%02x' % len(out_points)

        for out_point in out_points:
            txout_hash = out_point[0]
            txout_index = out_point[1]
            if len(out_point) > 2:
                txin_sequence = out_point[2]
            else:
                txin_sequence = u'00000000'
            input_hex += txout_hash
            input_hex += self.hex_swap(u'%08x' % txout_index)
            input_hex += u'00'                          # length
            input_hex += txin_sequence                 # sequence

        return input_hex

    def get_outputs_hex_from_outputs(self, outputs):
        """
        Gets the hex encoded output section of a transaction
        :param outputs: array of output tuples
                        (script_pub_key_hex, output_value)
        :return: hex encoded outputs section of a transaction
        """

        if len(outputs) >= VARINT_LIMIT:
            raise ValueError("Number of outputs exceeded maximum supported %d >= %d", (len(outputs), VARINT_LIMIT))

        output_hex = u'%02x' % len(outputs)
        for output in outputs:

            output_script_pub_key = output[0]
            output_value = output[1]

            output_hex += self.hex_swap(u'%016x' % output_value)

            if len(output_script_pub_key) >= (VARINT_LIMIT * 2) or len(output[0]) % 2 != 0:
                raise ValueError("ScriptPubKey length exceeds maximum %d greater than %d or odd",
                                 (len(outputs), (VARINT_LIMIT * 2)))

            output_hex += u'%02x' % (len(output_script_pub_key) // 2)
            output_hex += output[0]

        return output_hex

    def get_unspent_out_points(self, value, fee=0):
        """
        Gets a set of unspent out_points with value of at least (value + fee)
        :param value: the required out_points value
        :param fee: the additional transaction fee
        :return: total_value, array of out_point tuples
                 (txin_hash, txin_index)
        """
        required_value = value + fee

        unspent_outputs = self.__rpc.listunspent(1)

        unspent_outputs.sort(key=lambda out: out[u'amount'])

        total_value = 0

        outputs = []

        for unspent in unspent_outputs:
            tx_hash = self.hex_swap(unspent[u'txid'])
            out_index = unspent[u'vout']
            out_amount = int(round(unspent[u'amount'] * self.__amount_multiplier, 0))

            outputs.append((tx_hash, out_index))

            total_value += out_amount

            if total_value >= required_value:
                return total_value, outputs

        return None, None

    def get_private_key(self, version=None, change=True):
        if change:
            address = self.__rpc.getrawchangeaddress()
        else:
            address = self.__rpc.getnewaddress()

        private_key = self.__rpc.dumpprivkey(address)

        decoded = binascii.hexlify(base58.decode(private_key))

        if version:
            if version != decoded[0:2]:
                raise ValueError("Unexpected private key version")

        compressed = decoded[-2:]
        if compressed != u'01':
            raise ValueError("Expected compressed bit to be set")

        decoded = decoded[2:-2]
        if len(decoded) != 64:
            raise ValueError("Unexpected private key length")

        secexp = int(decoded, 16)

        return ecdsa.SigningKey.from_secret_exponent(secexp, ecdsa.curves.SECP256k1)

    def get_raw_pub_key(self, change=True):
        """
        Get a public key from the wallet
        :param change: use change pool
        :return: hex_encoded public key
        """
        if change:
            address = self.__rpc.getrawchangeaddress()
        else:
            address = self.__rpc.getnewaddress()
        validated_address = self.__rpc.validateaddress(address)

        return validated_address[u'pubkey']

    def get_der_key_from_ecdsa_key(self, key):
        """
        Gets a canonical DER encoded public key from a python-ecdsa key
        :param key:
        :return:
        """
        hex_key = binascii.hexlify(key.verifying_key.to_string())
        if len(hex_key) != 128:
            raise Exception

        odd = int(hex_key[126:128], 16) % 2 != 0

        hex_key = hex_key[0:64]
        if odd:
            hex_key = u'03' + hex_key
        else:
            hex_key = u'02' + hex_key
        return hex_key

    def get_pay_to_pub_key_script_pub_key(self, pub_key):
        """
        Gets hex encoded script_pub_key for pay to public key
        :param pub_key: hex encoded compressed DER public key
        :return: hex encoded script_pub_key
        """
        if len(pub_key) != 66:
            raise Exception

        return OP_PUSH(pub_key) + OP_CHECKSIG()

    def get_pay_to_pub_key_output(self, pub_key, value):
        """
        Gets output that pays to a public key
        :param pub_key: hex encoded compressed DER public key
        :param value: output values
        :return: single output tuples
                 (script_pub_key_hex, output_value)
        """
        if len(pub_key) != 66:
            raise Exception
        return self.get_pay_to_pub_key_script_pub_key(pub_key), value

    def get_pay_to_p2sh_script_pub_key(self, script_pub_key):
        """
        Gets hex encoded script_pub_key for a pay to P2SH
        :param script_pub_key: hex encoded script pub key
        :return: hex encoded script_pub_key
        """
        p2sh_hash = Hash160(binascii.unhexlify(script_pub_key)).digest()
        return OP_HASH160() + OP_PUSH(binascii.hexlify(p2sh_hash)) + OP_EQUAL()

    def get_pay_to_p2sh_output(self, script_pub_key, value):
        """
        Gets output that pays to a public key
        :param script_pub_key: hex encoded script pub key
        :param value: output values
        :return: single output tuples
                 (script_pub_key_hex, output_value)
        """
        return self.get_pay_to_p2sh_script_pub_key(script_pub_key), value

    def create_raw_transaction(self, out_points, outputs):
        """
        Gets a hex encoded raw transaction
        :param out_points: array of out_point tuples
                           (txout_hash, txout_index) or
                           (txout_hash, txout_index, txin_sequence)
        :param outputs: array of output tuples
                        (script_pub_key_hex, output_value)
        :return:
        """
        raw_tx = u'01000000'            # version 1

        raw_tx += self.get_inputs_hex_from_out_points(out_points)
        raw_tx += self.get_outputs_hex_from_outputs(outputs)
        raw_tx += u'00000000'              # locktime

        return raw_tx

    def create_pay_to(self, outputs, fee=0, lock=False):
        """
        Creates a transaction which pays to a set of outputs
        :param outputs: array of output tuples
                        (script_pub_key_hex, output_value)
        :param fee: the fee to include
        :return: hex_encoded raw transaction
        """
        fee = int(round(fee))
        total_outputs = 0
        for output in outputs:
            total_outputs += output[1]

        inputs_value, out_points = self.get_unspent_out_points(total_outputs + fee)

        if not out_points:
            return None

        for out_point in out_points:
            self.lockunspent(out_point[0], out_point[1])

        change_value = inputs_value - total_outputs - fee

        if change_value < 0:
            return None

        change_key = self.get_raw_pub_key()

        ## actually do outputs
        outputs.append(self.get_pay_to_pub_key_output(change_key, change_value))

        return self.create_raw_transaction(out_points, outputs)

    def pay_to(self, outputs, fee=0):
        """
        Creates and sends a transactions which pays to a set of outputs
        :param outputs: array of output tuples
                        (script_pub_key_hex, output_value)
        :param fee: the fee to include
        :return: hex_encoded raw transaction
        """
        raw_tx = self.create_pay_to(outputs, fee)
        if raw_tx:
            signed_tx = self.sign_transaction_by_server(raw_tx)
            if signed_tx:
                self.__rpc.sendrawtransaction(signed_tx)
                return signed_tx
        return None

    def send_raw_transaction(self, transaction):
        self.__rpc.sendrawtransaction(transaction)

    def get_rpc(self):
        """
        Gets the RPC instance
        :return:
        """
        return self.__rpc

    def sign_transaction_by_server(self, raw_tx):
        """
        Sends a raw transaction to the server for signing
        :param raw_tx: hex encoded raw transaction
        :return: hex encoded signed raw transaction or None on failure
        """
        try:
            response = self.__rpc.signrawtransaction(raw_tx)
            if response[u'complete']:
                return response[u'hex']
        except authproxy.JSONRPCException as e:
            pass

        return None

    def sign_transaction_input(self, transaction, script_pub_key, index, key):
        """
        Signs a transaction input with a given key
        :param transaction: hex encoded transaction to sign
        :param script_pub_key: script_pub_key of input
        :param index: input index
        :param key: python-ecdsa private key
        :return: hex encoded signature (r, s)
        """
        transaction = self.set_sig_script(transaction, script_pub_key, index) + u'01000000'
        transaction_bin = binascii.unhexlify(transaction)
        sig = key.sign_deterministic(transaction_bin, DoubleSHA256)
        sig = self.get_sec_sig_from_raw_sig(binascii.hexlify(sig))

        # print ("Hashing %s" % (binascii.hexlify(transaction_bin)))
        # print ("Sig hash %s" % (binascii.hexlify(DoubleSHA256(transaction_bin).digest())))
        # print ("Key %s" % (self.get_der_key_from_ecdsa_key(key)))

        return sig

    def strip_zeros(self, hex_str):
        """
        Removes leading zeros from (or adds 1 to) a hex encoded byte array for canonical SEC compliance
        :param hex_str: hex encoded big endian integer
        :return: hex encoded integer with minimal leading zeros
        """
        hex_bin = binascii.unhexlify(hex_str)
        i = 0
        while hex_bin[i] == b"\x00":
            i += 1

        if ord(hex_bin[i]) >= 0x80:
            if i == 0:
                hex_bin = b"\x00" + hex_bin
            else:
                hex_bin = hex_bin[i - 1:]
        else:
            hex_bin = hex_bin[i:]

        return binascii.hexlify(hex_bin)

    def get_sec_sig_from_raw_sig(self, sig):
        """
        Gets a hex encoded SEC signature from a hex encoded python-ecdsa
        :param sig: python-ecdsa hex encoded signature
        :return: hex encoded sec signature
        """
        r = sig[0:64]
        s = sig[64:128]

        r = self.strip_zeros(r)
        s = self.strip_zeros(s)

        total_length = 4 + (len(r) // 2) + (len(s) // 2)

        sig = u'30'
        sig += '%02x' % total_length
        sig += '02'
        sig += '%02x' % (len(r) // 2)
        sig += r
        sig += '02'
        sig += '%02x' % (len(s) // 2)
        sig += s
        sig += u'01'

        return sig

    def add_signatures_to_raw_transaction(self, transaction, index, signatures):
        """
        Adds a array of hex encoded SEC signatures to a raw transaction
        :param transaction: hex encoded transaction
        :param index: input index
        :param signatures: array of hex encoded signatures
        :return: raw transaction with signatures added
        """
        sig_script = u''
        for sig in signatures:
            sig_script += OP_PUSH(sig)
        return self.set_sig_script(transaction, sig_script, index)

    def set_sig_script(self, transaction, sig_script, index):
        """
        Sets the sig script in a raw transaction
        :param transaction: hex encoded transaction
        :param sig_script: hex encoded sig_script
        :param index: input index
        :return: raw transaction with sig_script set
        """
        in_count = int(transaction[8:10], 16)
        if index >= in_count:
            raise Exception

        i = 10

        while index > 0:
            script_len = int(transaction[i+72:i+74], 16)
            if script_len >= VARINT_LIMIT:
                raise ValueError("Script length exceeds maximum for var_int %d >= %d" % (script_len, VARINT_LIMIT))

            i += 36 * 2
            i += 2
            i += script_len * 2
            i += 4 * 2

            index -= 1

        if len(sig_script) >= VARINT_LIMIT * 2:
            raise ValueError("Script length exceeds maximum for var_int %d >= %d" % (len(sig_script) // 2, VARINT_LIMIT))

        sig_script = '%02x%s' % (len(sig_script) // 2, sig_script)

        if transaction[i+72:i+74] != u'00':
            raise ValueError("Transaction input %s is not empty" % index)

        return transaction[0:i + 72] + sig_script + transaction[i+74:]

