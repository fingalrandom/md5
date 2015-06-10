import sha1
import hashlib
import os

def testSHA1_1 ():
    test_text = os.urandom(50)
    m = hashlib.sha1(test_text).hexdigest()
    
    assert m == sha1.hash_in_hex(sha1.sha1(test_text))

def testSHA1_2 ():
    test_text = os.urandom(100)
    m = hashlib.sha1(test_text).hexdigest()
    
    assert m == sha1.hash_in_hex(sha1.sha1(test_text))

def testSHA_3 ():
    test_text = os.urandom(150)
    m = hashlib.sha1(test_text).hexdigest()
    
    assert m == sha1.hash_in_hex(sha1.sha1(test_text))

