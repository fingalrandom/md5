import md5
import hashlib
import os


def testMD51():
    test_text = os.urandom(44)
    m = hashlib.md5(test_text).hexdigest()
    assert m == md5._hexHash(md5.md5(test_text))


def testMD52():
    test_text = os.urandom(99)
    m = hashlib.md5(test_text).hexdigest()
    assert m == md5._hexHash(md5.md5(test_text))


def testMD53():
    test_text = os.urandom(222)
    m = hashlib.md5(test_text).hexdigest()
    assert m == md5._hexHash(md5.md5(test_text))
