from __future__ import absolute_import, division, print_function, unicode_literals

import json_server
import bitcoin
import hashlib

import ecdsa
import ecdsa.curves

import binascii
import argparse


HOSTNAME = "localhost"
PORT = 80

MULTIPLIER = 100000000

if __name__ == '__main__':

    parser = argparse.ArgumentParser("Coin Trader")

    parser.add_argument('-user', nargs=1, help=u'username', required=True, type=unicode)
    parser.add_argument('-pass', nargs=1, help=u'password', required=True, type=unicode)
    parser.add_argument('-host', nargs=1, help=u'server hostname', default=u'localhost', type=unicode)
    parser.add_argument('-port', nargs=1, help=u'server port', default=18332, type=int)

    args = vars(parser.parse_args())

    print (args)

    i = int('9190bca67fd34203964cb5196f8152ad319aec5e9a1f868bc0193cf03305d845', 16)

    key1 = ecdsa.SigningKey.from_secret_exponent(i, ecdsa.curves.SECP256k1)

    user_pass_string = u"http://%s:%s@%s:%s" % (args[u'user'][0], args[u'pass'][0], args[u'host'][0], args[u'port'][0])

    rpc = bitcoin.RPCInterface(user_pass_string, MULTIPLIER)

    pub_key_sec = rpc.get_der_key_from_ecdsa_key(key1)

    # outputs = [rpc.get_pay_to_pub_key_output(pub_key_sec, 0.001 * MULTIPLIER)]
    p2sh_script_pub_key = rpc.get_pay_to_pub_key_script_pub_key(pub_key_sec)
    outputs = [rpc.get_pay_to_p2sh_output(p2sh_script_pub_key, 0.001 * MULTIPLIER)]

    raw_tx = rpc.pay_to(outputs, 0.0001 * MULTIPLIER)
    # raw_tx = True

    if not raw_tx:
        print ("Insufficient transaction outputs to pay to outputs")
        exit()

    tx_hash = bitcoin.DoubleSHA256(binascii.unhexlify(raw_tx)).hexdigest()

    # tx_hash = rpc.hex_swap(u'444ded616aa3f05af4875bc2206ebd4c24c0d3e64e27a2a3e8c3441248828ba6')

    inputs = [(tx_hash, 0)]

    payment_address = rpc.get_raw_pub_key(False)
    payment_outputs = [rpc.get_pay_to_pub_key_output(payment_address, 0.0009 * MULTIPLIER)]

    transaction = rpc.create_raw_transaction(inputs, payment_outputs)

    # raw_sig = rpc.sign_transaction_input(transaction, outputs[0][0], 0, key1)
    raw_sig = rpc.sign_transaction_input(transaction, p2sh_script_pub_key, 0, key1)

    sig = rpc.get_sec_sig_from_raw_sig(raw_sig)
    sig2 = p2sh_script_pub_key

    transaction = rpc.add_signatures_to_raw_transaction(transaction, 0, [sig, sig2])

    rpc.get_rpc().sendrawtransaction(transaction)

    # httpd = json_server.JSONHTTPServer('user', 'pass', (HOSTNAME, PORT), json_server.JSONHandler)
    # try:
    #    httpd.serve_forever()
    # except KeyboardInterrupt:
    #    pass
    # httpd.server_close()
