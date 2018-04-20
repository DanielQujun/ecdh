#!/usr/bin/env python
# -*- coding: UTF-8 -*-

try:
    from hashlib import md5
except ImportError:
    import md5
from util.openssl_wrapper import OpenSSL
from ctypes import *

class Ecdh(object):
    def __init__(self, curve='secp224r1'):
        self.pubkey = self.prikey = None
        self.curveID = OpenSSL.curves[curve]

    def gen_ec_keypair(self, ):
        self.pubkey, self.prikey = b'', b''  # just avoid call do_ECDHshare() before gen_ec_keypair()
        ec_obj = OpenSSL.EC_KEY_new_by_curve_name(self.curveID)  # EC_KEY *EC_KEY_new_by_curve_name(int nid)
        flag = OpenSSL.EC_KEY_generate_key(ec_obj)  # int EC_KEY_generate_key(EC_KEY *eckey)
        if flag != 1:
            OpenSSL.EC_KEY_free(ec_obj)
            return None, None
        priKey = create_string_buffer(b'0', 512)   # dh private_key buf
        pubKey = create_string_buffer(b'0', 128)   # dh public_key buf
        pri = cast(priKey, POINTER(c_char * 512))  # convert to pointer
        pub = cast(pubKey, POINTER(c_char * 128))
        # int i2o_ECPublicKey(EC_KEY *key, unsigned char **out);
        LenPub = OpenSSL.i2o_ECPublicKey(ec_obj, None)        # if out==NULL , return length
        flag   = OpenSSL.i2o_ECPublicKey(ec_obj, byref(pub))  # if out!=NULL , return flag
        if LenPub == 0 or flag == 0:
            OpenSSL.EC_KEY_free(ec_obj)
            return None, None
        # int i2d_ECPrivateKey(EC_KEY *key, unsigned char **out);
        LenPri = OpenSSL.i2d_ECPrivateKey(ec_obj, None)        # if out==NULL , return length
        flag   = OpenSSL.i2d_ECPrivateKey(ec_obj, byref(pri))  # if out!=NULL , return flag
        OpenSSL.EC_KEY_free(ec_obj)  # clear mem
        if LenPri == 0 or flag == 0:
            return None, None
        self.prikey = string_at(priKey, size=LenPri)  # fetch data
        self.pubkey = string_at(pubKey, size=LenPub)
        return self.prikey, self.pubkey

    def do_ECDHshare(self, server_ECDH_pub, priKey=None):
        OUTLEN = 16
        EcdhShareKey = b''
        # EC_KEY *EC_KEY_new_by_curve_name(int nid)
        server_ec = OpenSSL.EC_KEY_new_by_curve_name(self.curveID)
        if not server_ec:
            return None, None
        server_pubLen = len(server_ECDH_pub)
        server_pub = cast(server_ECDH_pub, POINTER(c_char * server_pubLen))  # push key data into c_char array
        # EC_KEY *o2i_ECPublicKey(EC_KEY **a, const unsigned char **in, long len) # convert key data to EC curve
        server_ec = c_void_p(server_ec)
        server_ec = OpenSSL.o2i_ECPublicKey(byref(server_ec), byref(server_pub), c_long(server_pubLen))
        if not server_ec:
            return None, None

        pri_ec = OpenSSL.EC_KEY_new_by_curve_name(self.curveID)
        if not pri_ec:
            return None, None
        if not priKey:
            priKey = self.prikey
        priKey_len = len(priKey)
        priKey = cast(priKey, POINTER(c_char * priKey_len))  # push key data into c_char array

        # EC_KEY *d2i_ECPrivateKey(EC_KEY **a, const unsigned char **in, long len)  # convert key data to EC curve
        pri_ec = c_void_p(pri_ec)
        pri_ec = OpenSSL.d2i_ECPrivateKey(byref(pri_ec), byref(priKey), c_long(priKey_len))
        if not pri_ec:
            return None, None

        # int ECDH_compute_key(void *out, size_t outlen,
        #           const EC_POINT pub_key, EC_KEY ecdh,
        #           void (KDF) (const void in, size_t inlen, void out, size_t *outlen));
        ECDH_compute_key = OpenSSL.ECDH_compute_key
        ECDH_compute_key.argtypes = (c_void_p, c_size_t, c_void_p, c_void_p, c_void_p)
        ECDH_compute_key.restype = c_int
        # void *(*KDF) (const void *in, size_t inlen, void *out, size_t *outlen))
        KDF = CFUNCTYPE(c_void_p,  # return type
                        # c_void_p, c_size_t, POINTER(c_char), POINTER(c_size_t))
                        c_void_p, c_size_t, c_void_p, POINTER(c_size_t))
        @KDF
        def mykdf(_in, _inlen, out, outlen):
            nonlocal OUTLEN, EcdhShareKey
            data = string_at(_in, size=_inlen)
            md5_obj = md5()
            md5_obj.update(data)
            EcdhShareKey = md5_obj.digest()
            # if len(outdata) == OUTLEN:
            #     outlen.contents = c_size_t(OUTLEN)
            #     data = cast(data, POINTER(c_char))
            #     out.contents = data.contents
            #     out.contents = outdata
            #     memset(byref(out), data, sizeof(c_char * OUTLEN))
            # memset(outlen, c_size_t(OUTLEN), sizeof(c_size_t))
            # outlen = POINTER(c_int(len(out)))
            return out

        ShareKey_buf = create_string_buffer(b'\000', 64)
        ShareKey_p = pointer(ShareKey_buf)
        outlen = c_size_t(OUTLEN)
        # const EC_POINT *EC_KEY_get0_public_key(const EC_KEY *key)  # get share point 0
        server_ECpoint = OpenSSL.EC_KEY_get0_public_key(server_ec)
        server_ECpoint = c_void_p(server_ECpoint)
        # int ECDH_compute_key(void *out, size_t outlen, const EC_POINT *pub_key,
        #              EC_KEY *eckey, void *(*KDF) )
        ECDH_compute_key(ShareKey_p, outlen, server_ECpoint, pri_ec, mykdf)
        OpenSSL.EC_KEY_free(server_ec), OpenSSL.EC_KEY_free(pri_ec)
        if len(EcdhShareKey) == OUTLEN:
            # EcdhShareKey = ShareKey_buf[:OUTLEN]
            return EcdhShareKey
        else:
            return None


if __name__ == '__main__':
    '''
    simple Test case
    '''
    EcdhPriKey = b'0\x82\x01D\x02\x01\x01\x04\x1c\xb9~,]@\x81\xe2\x04\x86\xdd\xc4\r\xa3\xaad\xc1\x8b\xa4\xb3\xef\x1ce\x9ck\xe6\x91\xc5\x1f\xa0\x81\xe20\x81\xdf\x02\x01\x010(\x06\x07*\x86H\xce=\x01\x01\x02\x1d\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x010S\x04\x1c\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xfe\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xfe\x04\x1c\xb4\x05\n\x85\x0c\x04\xb3\xab\xf5A2VPD\xb0\xb7\xd7\xbf\xd8\xba\'\x0b9C#U\xff\xb4\x03\x15\x00\xbdq4G\x99\xd5\xc7\xfc\xdcE\xb5\x9f\xa3\xb9\xab\x8fj\x94\x8b\xc5\x049\x04\xb7\x0e\x0c\xbdk\xb4\xbf\x7f2\x13\x90\xb9J\x03\xc1\xd3V\xc2\x11"42\x80\xd6\x11\\\x1d!\xbd7c\x88\xb5\xf7#\xfbL"\xdf\xe6\xcdCu\xa0Z\x07GdD\xd5\x81\x99\x85\x00~4\x02\x1d\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x16\xa2\xe0\xb8\xf0>\x13\xdd)E\\\\*=\x02\x01\x01\xa1<\x03:\x00\x04\xabd#\x90\xd3H3\xf5o\xe8.\t\x0f\xa0\x90\x8f\xb7-t\x85\xf83\xd8\x0b\xa7\xe5{\xf6\xdd%\xa4\xd6\xaa!\xb7\x8f\xfa\xdd\xe4]\x81q\xb6\xb4|E\xdc\xe0h\x14o\x98\xb4\xa1\xf3>'
    EcdhPubKey = b'\x04\xabd#\x90\xd3H3\xf5o\xe8.\t\x0f\xa0\x90\x8f\xb7-t\x85\xf83\xd8\x0b\xa7\xe5{\xf6\xdd%\xa4\xd6\xaa!\xb7\x8f\xfa\xdd\xe4]\x81q\xb6\xb4|E\xdc\xe0h\x14o\x98\xb4\xa1\xf3>'
    ServerEcdhPubKey = b'\x04\xea/\xe0\xf3\xb0\xfb2]n-Y\x80\xa4\xea\xaa\xd2\xf6\x11\x95\xa7o\xf6Zj-\x8d\xdd\x1c\x84\xaa\x9a\n\xdf\xdf\x1f\x95h\xc0w<\x9du$\xe9\xfd\xf2\x0c%x\xab0\xf4@\xed\xa0g'
    EcdhShareKey = b'\x7f+\xcc\x0b\x05\x0fC=?3\x90\xb3Bt\x89\xc8'

    EcdhPriKey2 = b'0\x82\x01D\x02\x01\x01\x04\x1c\xd5g\xe2\xdc\t~\x88\x06apv6\x04\x03\xb6b\xb7^&\xd3Y3\x1c)R\x8d\xac8\xa0\x81\xe20\x81\xdf\x02\x01\x010(\x06\x07*\x86H\xce=\x01\x01\x02\x1d\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x010S\x04\x1c\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xfe\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xfe\x04\x1c\xb4\x05\n\x85\x0c\x04\xb3\xab\xf5A2VPD\xb0\xb7\xd7\xbf\xd8\xba\'\x0b9C#U\xff\xb4\x03\x15\x00\xbdq4G\x99\xd5\xc7\xfc\xdcE\xb5\x9f\xa3\xb9\xab\x8fj\x94\x8b\xc5\x049\x04\xb7\x0e\x0c\xbdk\xb4\xbf\x7f2\x13\x90\xb9J\x03\xc1\xd3V\xc2\x11"42\x80\xd6\x11\\\x1d!\xbd7c\x88\xb5\xf7#\xfbL"\xdf\xe6\xcdCu\xa0Z\x07GdD\xd5\x81\x99\x85\x00~4\x02\x1d\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x16\xa2\xe0\xb8\xf0>\x13\xdd)E\\\\*=\x02\x01\x01\xa1<\x03:\x00\x04($\xaex HB~\x8d\xbb\x81\xaa$\xac\xc5G%\x7f\x9fnU\xa3\xa6g\xa5\nj~\xb6:\x99\xcf4r-\x0e/\xb4\x01\xebrf{\xef[\x9dMsf8\xadD\xea\x17f\x8d'
    EcdhPubKey2 = b'\x04($\xaex HB~\x8d\xbb\x81\xaa$\xac\xc5G%\x7f\x9fnU\xa3\xa6g\xa5\nj~\xb6:\x99\xcf4r-\x0e/\xb4\x01\xebrf{\xef[\x9dMsf8\xadD\xea\x17f\x8d'
    ServerEcdhPubKey2 = b'\x04~]\xaf\xe7|\x93\x80Y-[Nz\xb7\x0e\x80\xd4\x00\xb4_@\xef+!\xad\xbb0S\xd1\xcc\x04\xb9\x01\x9c=\x97WXZ1\xebC\x95\xa6\xac)@mOEa\x94\xdbQ\xcb\xd2\xf4'
    EcdhShareKey2 = b'\xb0)v_\xd6W\x1a{\xc9\x07EcP\xa9F%'

    ec = Ecdh()

    pri, pub = ec.gen_ec_keypair()  # test PASSED
    print(len(pri), pri, '\n', len(pub), pub)
    assert len(pri) == len(EcdhPriKey2) and type(pri) == type(EcdhPriKey2) and (
        len(pub) == len(EcdhPubKey2) and type(pub) == type(EcdhPubKey2)), 'generate key_pair failed'

    shared = ec.do_ECDHshare(ServerEcdhPubKey2, EcdhPriKey2)  # FAILED
    print(len(shared), shared)
    assert len(shared) == len(EcdhShareKey2) and type(shared) == type(EcdhShareKey2), 'ecdh failed'
