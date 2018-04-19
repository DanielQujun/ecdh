#!/usr/bin/env python
# -*- coding: UTF-8 -*-

import hashlib
from util.openssl_wrapper import OpenSSL
import platform
import ctypes
from ctypes import *

class Ecdh(object):
    def __init__(self, curve='secp224r1'):
        self.pubkey = None
        self.prikey = None
        self.shake_hands = None
        self.curveID = OpenSSL.curves[curve]

    def gen_ec_keypair(self, ):
        ec_obj = OpenSSL.EC_KEY_new_by_curve_name(self.curveID)  # EC_KEY *EC_KEY_new_by_curve_name(int nid)
        flag = OpenSSL.EC_KEY_generate_key(ec_obj)  # int EC_KEY_generate_key(EC_KEY *eckey)
        if flag != 1:
            OpenSSL.EC_KEY_free(ec_obj)
            return None, None
        priKey = ctypes.create_string_buffer(b'\000', 512)  # dh private_key buf
        pubKey = ctypes.create_string_buffer(b'\000', 512)  # dh public_key buf
        pri = ctypes.cast(priKey, ctypes.POINTER(ctypes.c_char * 512))  # convert to pointer
        pub = ctypes.cast(pubKey, ctypes.POINTER(ctypes.c_char * 512))
        # int i2o_ECPublicKey(EC_KEY *key, unsigned char **out);
        LenPub = OpenSSL.i2o_ECPublicKey(ec_obj, None)               # if out==NULL , return length
        flag   = OpenSSL.i2o_ECPublicKey(ec_obj, ctypes.byref(pub))  # if out!=NULL , return flag
        if LenPub == 0 or flag == 0:
            OpenSSL.EC_KEY_free(ec_obj)
            return None, None
        # int i2d_ECPrivateKey(EC_KEY *key, unsigned char **out);
        LenPri = OpenSSL.i2d_ECPrivateKey(ec_obj, None)
        flag   = OpenSSL.i2d_ECPrivateKey(ec_obj, ctypes.byref(pri))
        OpenSSL.EC_KEY_free(ec_obj)
        if LenPri == 0 or flag == 0:
            return None, None
        else:
            EcdhPriKey = priKey[:LenPri]
            EcdhPubKey = pubKey[:LenPub]
            return EcdhPriKey, EcdhPubKey

    def do_ECDHshare(self, server_ECDH_pub, priKey=None):
        OUTLEN = 16
        server_ECDH = server_ECDH_pub
        # EC_KEY *EC_KEY_new_by_curve_name(int nid)
        server_ec = OpenSSL.EC_KEY_new_by_curve_name(self.curveID)
        if not server_ec:
            return None, None
        server_pubLen = len(server_ECDH_pub)
        server_pub = ctypes.cast(server_ECDH_pub, ctypes.POINTER(ctypes.c_char * server_pubLen))
        # EC_KEY *o2i_ECPublicKey(EC_KEY **a, const unsigned char **in, long len)
        server_ec = c_void_p(server_ec)
        server_ec = OpenSSL.o2i_ECPublicKey(ctypes.byref(server_ec),  # 还原对方的 EC 数据
                                            ctypes.byref(server_pub), ctypes.c_long(server_pubLen))
        if not server_ec:
            return None, None
        # const EC_POINT *EC_KEY_get0_public_key(const EC_KEY *key)  获取公共点
        # server_ec = c_void_p(server_ec)


        pri_ec = OpenSSL.EC_KEY_new_by_curve_name(self.curveID)
        if not pri_ec:
            return None, None
        if not priKey:
            priKey = self.prikey
        priKey_len = len(priKey)
        priKey = ctypes.cast(priKey, ctypes.POINTER(ctypes.c_char * priKey_len))  # 将数据压入 C 缓存
        # EC_KEY *d2i_ECPrivateKey(EC_KEY **a, const unsigned char **in, long len)
        pri_ec = c_void_p(pri_ec)
        pri_ec = OpenSSL.d2i_ECPrivateKey(ctypes.byref(pri_ec),   # 还原 自己的 EC 数据
                                          ctypes.byref(priKey), ctypes.c_long(priKey_len))
        if not pri_ec:
            return None, None

        ECDH_compute_key = OpenSSL.ECDH_compute_key
        # void *(*KDF) (const void *in, size_t inlen, void *out, size_t *outlen))
        # KDF = CFUNCTYPE(c_void_p,  # return type
        #                 c_void_p, c_size_t, c_void_p, POINTER(c_size_t))

        KDF = WINFUNCTYPE(c_void_p,  # return type
                        c_void_p, c_size_t, c_void_p, POINTER(c_size_t))
        @KDF
        def mykdf(_in, _inlen, out, outlen):
            nonlocal OUTLEN
            data = ctypes.string_at(_in, size=_inlen)
            md5 = hashlib.md5()
            md5.update(data)
            print(md5.digest())
            outlen.contents = c_size_t(OUTLEN)
            ctypes.memset(outlen, c_size_t(OUTLEN))
            outlen = POINTER(c_int(len(out)))
            return out
        # int ECDH_compute_key(void *out, size_t outlen,
        #           const EC_POINT pub_key, EC_KEY ecdh,
        #           void (KDF) (const void in, size_t inlen, void out, size_t *outlen));
        ECDH_compute_key.argtypes = (c_void_p, c_size_t,
                                     c_void_p, c_void_p, c_void_p)
        ECDH_compute_key.restype = c_int
        ShareKey_buf = ctypes.create_string_buffer(b'\000', 128)
        # ShareKey_p = c_void_p(ShareKey_buf)
        # ShareKey_p = ctypes.cast(ShareKey_buf, ctypes.POINTER(ctypes.c_char * 128))
        ShareKey_p = ctypes.pointer(ShareKey_buf)

        outlen = c_size_t(OUTLEN)
        server_ECpoint = OpenSSL.EC_KEY_get0_public_key(server_ec)

        server_ECpoint = c_void_p(server_ECpoint)

        pri_ec_p = c_void_p(pri_ec)
        free_space_pointer = ctypes.c_ulonglong(0)

        # int ECDH_compute_key(void *out, size_t outlen, const EC_POINT *pub_key,
        #              EC_KEY *eckey, void *(*KDF) )
        result = ECDH_compute_key(ShareKey_p, outlen, server_ECpoint, pri_ec,
                                  mykdf)
        OpenSSL.EC_KEY_free(server_ec), OpenSSL.EC_KEY_free(pri_ec)
        if result == OUTLEN:
            EcdhShareKey = ShareKey_buf[:OUTLEN]
        else:
            return None

        #     try:
        #         EcdhShareKey = ShareKey_buf[:OUTLEN]
        #     except:
        #         pass
        # if len(EcdhShareKey) == OUTLEN:
        #     return EcdhShareKey
        # else:
        #     return None

    #   ECDH_compute_key((void *)szShareKey, MD5_DIGEST_LENGTH, point, pri_ec_key, KDF_MD5))

if __name__ == '__main__':
    EcdhPriKey = b'0\x82\x01D\x02\x01\x01\x04\x1c\xb9~,]@\x81\xe2\x04\x86\xdd\xc4\r\xa3\xaad\xc1\x8b\xa4\xb3\xef\x1ce\x9ck\xe6\x91\xc5\x1f\xa0\x81\xe20\x81\xdf\x02\x01\x010(\x06\x07*\x86H\xce=\x01\x01\x02\x1d\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x010S\x04\x1c\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xfe\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xfe\x04\x1c\xb4\x05\n\x85\x0c\x04\xb3\xab\xf5A2VPD\xb0\xb7\xd7\xbf\xd8\xba\'\x0b9C#U\xff\xb4\x03\x15\x00\xbdq4G\x99\xd5\xc7\xfc\xdcE\xb5\x9f\xa3\xb9\xab\x8fj\x94\x8b\xc5\x049\x04\xb7\x0e\x0c\xbdk\xb4\xbf\x7f2\x13\x90\xb9J\x03\xc1\xd3V\xc2\x11"42\x80\xd6\x11\\\x1d!\xbd7c\x88\xb5\xf7#\xfbL"\xdf\xe6\xcdCu\xa0Z\x07GdD\xd5\x81\x99\x85\x00~4\x02\x1d\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x16\xa2\xe0\xb8\xf0>\x13\xdd)E\\\\*=\x02\x01\x01\xa1<\x03:\x00\x04\xabd#\x90\xd3H3\xf5o\xe8.\t\x0f\xa0\x90\x8f\xb7-t\x85\xf83\xd8\x0b\xa7\xe5{\xf6\xdd%\xa4\xd6\xaa!\xb7\x8f\xfa\xdd\xe4]\x81q\xb6\xb4|E\xdc\xe0h\x14o\x98\xb4\xa1\xf3>'
    EcdhPubKey = b'\x04\xabd#\x90\xd3H3\xf5o\xe8.\t\x0f\xa0\x90\x8f\xb7-t\x85\xf83\xd8\x0b\xa7\xe5{\xf6\xdd%\xa4\xd6\xaa!\xb7\x8f\xfa\xdd\xe4]\x81q\xb6\xb4|E\xdc\xe0h\x14o\x98\xb4\xa1\xf3>'
    ServerEcdhPubKey = b'\x04\xea/\xe0\xf3\xb0\xfb2]n-Y\x80\xa4\xea\xaa\xd2\xf6\x11\x95\xa7o\xf6Zj-\x8d\xdd\x1c\x84\xaa\x9a\n\xdf\xdf\x1f\x95h\xc0w<\x9du$\xe9\xfd\xf2\x0c%x\xab0\xf4@\xed\xa0g'
    EcdhShareKey = b'\x7f+\xcc\x0b\x05\x0fC=?3\x90\xb3Bt\x89\xc8'

    ec = Ecdh()
    pri, pub = ec.gen_ec_keypair()  # test PASSED

    assert len(pri) == len(EcdhPriKey) and type(pri) == type(EcdhPriKey) and (
        len(pub) == len(EcdhPubKey) and type(pub) == type(EcdhPubKey)), 'generate key_pair failed'

    shared = ec.do_ECDHshare(ServerEcdhPubKey, EcdhPriKey)  # FAILED
    assert len(shared) == len(EcdhShareKey) and type(shared) == type(EcdhShareKey), 'ecdh failed'