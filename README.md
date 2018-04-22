# ecdh, just for learn

Well, I made this project because find a python ecdh package is unbelievably hard:

- https://github.com/pyca/cryptography/issues/4190    can't
- https://github.com/vbwagner/ctypescrypto    can't
- https://gitlab.com/m2crypto/m2crypto    just for python2, can't

So I compile OpenSSL in Windows/Linux/MacOS, use Ctypes moudle wrap it, then make a python one.


好吧，我建立这个工程，只是因为 找个 python 的 ECDH 包 太难了。所以，我把 OpenSSL 在各个平台下编译了，并且用 ctypes 做了转接，然后做出了跨平台的 python模块。如果你有兴趣，可以放到 PyPI

