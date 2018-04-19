#!/usr/bin/env python
# -*- coding: UTF-8 -*-

def ecdh_key(a_privkey, b_pubkey):
    # keys should be in binary format
    a_curve = int(a_privkey[0:2].encode('hex'), 16)
    b_curve = int(b_pubkey[0:2].encode('hex'), 16)
    if a_curve != b_curve:
        raise Exception("ECDH Error: Both key must have the save curve type.")

    sx = int(b_pubkey[2:4].encode('hex'), 16)
    sy = int(b_pubkey[4 + sx:sx + 6].encode('hex'), 16)
    pub_x, pub_y = b_pubkey[4:4 + sx], b_pubkey[6 + sx:6 + sx + sy]

    b_key = OpenSSL.EC_KEY_new_by_curve_name(b_curve)
    _pub_x = OpenSSL.BN_bin2bn(pub_x, sx, 0)
    _pub_y = OpenSSL.BN_bin2bn(pub_y, sy, 0)
    _group = OpenSSL.EC_KEY_get0_group(b_key)
    _pubkey = OpenSSL.EC_POINT_new(_group)
    OpenSSL.EC_POINT_set_affine_coordinates_GFp(_group, _pubkey, _pub_x, _pub_y, 0)
    OpenSSL.EC_KEY_set_public_key(b_key, _pubkey)
    # OpenSSL.EC_KEY_check_key(b_key)

    s = int(a_privkey[2:4].encode('hex'), 16)
    priv = a_privkey[4:4 + s]
    a_key = OpenSSL.EC_KEY_new_by_curve_name(a_curve)
    _privkey = OpenSSL.BN_bin2bn(priv, len(priv), 0)
    OpenSSL.EC_KEY_set_private_key(a_key, _privkey)

    # ECDH
    OpenSSL.ECDH_set_method(a_key, OpenSSL.ECDH_OpenSSL())
    ecdh_buf = OpenSSL.malloc(0, s)  # computed buffer size should the same as key length
    ecdh_keylen = OpenSSL.ECDH_compute_key(ecdh_buf, s, _pubkey, a_key, 0)
    return ecdh_buf.raw


