from __future__ import absolute_import, division, print_function, unicode_literals

import json_server
import bitcoin
import trader

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

    user_pass_string = u"http://%s:%s@%s:%s" % (args[u'user'][0], args[u'pass'][0], args[u'host'][0], args[u'port'][0])

    rpc = bitcoin.RPCInterface(user_pass_string, MULTIPLIER)

    rpc.unlock_all_unspent()

    fast_trader = trader.ChainTrader(True,
                                     rpc, 0.001 * MULTIPLIER, 0.0001 * MULTIPLIER,
                                     rpc, 0.0015 * MULTIPLIER, 0.0001 * MULTIPLIER)

    slow_trader = trader.ChainTrader(False,
                                     rpc, 0.001 * MULTIPLIER, 0.0001 * MULTIPLIER,
                                     rpc, 0.0015 * MULTIPLIER, 0.0001 * MULTIPLIER)

    deterministic_keys = False
    send_bail_in = True

    if deterministic_keys:
        # For debug only
        fast_trader.generate_keys(20)
        slow_trader.generate_keys(10)
    else:
        fast_trader.generate_keys()
        slow_trader.generate_keys()

    hash_x = slow_trader.generate_hash_x()
    fast_trader.set_hash_x(hash_x)

    slow_pub_keys = slow_trader.get_public_keys()
    fast_pub_keys = fast_trader.get_public_keys()

    slow_trader.set_keys(fast_pub_keys)
    fast_trader.set_keys(slow_pub_keys)

    fast_bail_in = fast_trader.generate_bail_in_transaction(send_bail_in)
    slow_bail_in = slow_trader.generate_bail_in_transaction(send_bail_in)

    if send_bail_in:
        rpc.send_raw_transaction(slow_bail_in)
        rpc.send_raw_transaction(fast_bail_in)

        fast_trader.set_bail_in_hash(slow_trader.get_bail_in_hash())
        slow_trader.set_bail_in_hash(fast_trader.get_bail_in_hash())
    else:
        # Repeat for deterministic keys
        fast_bail_in_hash = rpc.hex_swap(u'd825cb85e9891b7a9fb524835ab13d10542f2bf65ba84cb0e4edae5fe9d37ab9')
        slow_bail_in_hash = rpc.hex_swap(u'6bf41af549e54f795bfedeb58a70e686d4da7e54520708791784b2511843aede')
        fast_trader._force_bail_in_hashes(fast_bail_in_hash, slow_bail_in_hash)
        slow_trader._force_bail_in_hashes(fast_bail_in_hash, slow_bail_in_hash)

    slow_trader.generate_transactions()
    fast_trader.generate_transactions()

    fast_sigs = fast_trader.sign_transactions()

    slow_sigs = slow_trader.sign_transactions()

    x = slow_trader.send_payout(fast_sigs)

    fast_trader.set_x(x)

    fast_trader.send_payout(slow_sigs)
