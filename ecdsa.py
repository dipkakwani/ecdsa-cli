"""
Implementation of elliptic curve digital signature algorithm (ECDSA).
Author: Diptanshu Kakwani
"""

import random
import hashlib
import logging, sys             # Debugging
import click                    # For command line interface
import cPickle as pickle        # Object serialization for saving and retrieving

logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)
logger = logging.getLogger()
logger.disabled = True

def extended_euclidean_algorithm(a, b):
    """
    Returns a 3-tuple (g, s, t) where g is the gcd of a and b, such that 
    g = s * a + t * b.
    """
    s, old_s = 0, 1
    t, old_t = 1, 0
    r, old_r = b, a

    while r != 0:
        quotient = old_r / r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t

    return old_r, old_s, old_t

def inverse_mod(n, p):
    """
    Returns multiplicative inverse of n modulo p.
    Raises ValueError if n and p are not coprime.
    """
    g, s, t = extended_euclidean_algorithm(n, p)
    if g != 1:
        raise ValueError('%s has no multiplicative inverse modulo %s' % (n, p))
    return s % p

class Point:
    """
    Represents a point in 2-dimensions by coordinates (x, y).
    """
    def __init__(self, x = 0, y = 0):
        self.x = x
        self.y = y

    def __eq__(self, other):
        return (self.x == other.x and self.y == other.y)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __str__(self):
        return "X: " + str(self.x) + " Y: " + str(self.y)

class elliptic_curve:
    """
    Represents an elliptic curve over prime field in the form 
    y^2 = x^3 + const_a * x + const_b
    where const_a and const_b are both prime, with the constraint
    (4 * a^3 + 27 * b^2) % p != 0 (to exclude singular curves)
    """
    def __init__(self, a, b, p, q, pnt):
        assert (4 * (a ** 3) + 27 * (b ** 2)) % p != 0
        self.const_a = a
        self.const_b = b
        self.p = p
        self.q = q
        self.A = pnt

    def point_doubling(self, a):
        """
        """
        s = (3 * a.x * a.x + self.const_a) % self.p
        s_denom = inverse_mod(2 * a.y, self.p)
        s = (s * s_denom) % self.p
        c = Point()
        c.x = (s * s - a.x - a.x) % self.p
        c.y = (s * (a.x - c.x) - a.y) % self.p
        return c

    def point_addition(self, a, b):
        """
        """
        assert a != b 
        s = (b.y - a.y) % self.p
        s_denom = inverse_mod(b.x - a.x, self.p)
        s = (s * s_denom) % self.p
        c = Point()
        c.x = (s * s - a.x - b.x) % self.p
        c.y = (s * (a.x - c.x) - a.y) % self.p
        return c

    def multiply(self, n, P):
        """
        """
        Q = Point(P.x, P.y)
        bin_str = "{0:b}".format(n)
        for i in range(1, len(bin_str)):
            Q = self.point_doubling(Q)
            if bin_str[i] == "1":
                Q = self.point_addition(Q, P)
        return Q

# Elliptic curve by Standards for Efficient Cryptography Group, also used by Bitcoin
secp256k1 = elliptic_curve(0, 7, 
                            0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f,
                            0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141, 
                            Point(0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
                                  0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8))

ec = secp256k1 # Elliptic curve to be used

def generate_keys():
    """
    Generates private and public key.
    """
    d = random.randint(1, ec.q - 1)
    B = ec.multiply(d, ec.A) 
    public_key = (ec.p, ec.const_a, ec.const_b, ec.q, ec.A, B)
    private_key = (d)
    logging.debug("Generated public key " + str(public_key))
    logging.debug("Generated private key " + str(private_key))
    return public_key, private_key

def signature_generation(msg, private_key):
    """
    Generates signature for a given message. Note that it will most likely
    return different signature even for the same message, since it uses a random
    integer as a parameter for generating the sign. This can be avoided by using 
    the hash of the message as that random parameter, but it is not defined so 
    in the standard ECDSA.
    """
    # Generate non-zero signature value
    while True:
        # Generate non-zero random value
        while True:
            k = random.randint(1, ec.q - 1)
            R = ec.multiply(k, ec.A)
            r = R.x
            if r % ec.q:
                break
        signature = (int(hashlib.sha256(msg).hexdigest(), 16) +\
                    private_key * r) % ec.q
        if signature:
            break
    k_inv = inverse_mod(k, ec.q)
    signature = (signature * k_inv) % ec.q
    logging.debug("Generated signature " + str(signature))
    return (r, signature)

def signature_verification(msg, signature, public_key):
    """
    Verifies the signature of a message by using the public key of the author.
    """
    w = inverse_mod(signature[1], ec.q)
    u1 = (w * int(hashlib.sha256(msg).hexdigest(), 16)) % ec.q
    u2 = (w * signature[0]) % ec.q
    P1 = ec.multiply(u1, ec.A)
    P2 = ec.multiply(u2, public_key[5])
    if P1 != P2:
        P = ec.point_addition(P1, P2)
    else:
        P = ec.point_doubling(P1)
    return P.x == (signature[0] % ec.q)

def save_object(filename, obj):
    """ Saves object _obj_ in the file. """
    with open(filename, 'wb') as output:
        pickle.dump(obj, output, pickle.HIGHEST_PROTOCOL)

def load_object(filename):
    """ Loads object from the file. """
    with open(filename, 'rb') as input:
        return pickle.load(input)

@click.group()
def main():
    """ Signature generation and verification through ECDSA"""
    pass

@main.command()
def keygen():
    """Generate a key pair"""
    public_key, private_key = generate_keys()
    save_object('public.key', public_key)
    save_object('private.key', private_key)
    print "Key pair generated successfully!"

@main.command()
def keys():
    """Get public and private keys"""
    public_key = load_object('public.key')
    private_key = load_object('private.key')
    print "Public Key: "
    for key in public_key:
        print key
    print "Private Key: " 
    print private_key

@main.command()
@click.option('--message', prompt=True, help='message to be signed')
def sign(message):
    """Sign a message"""
    private_key = load_object('private.key')
    signature = signature_generation(message, private_key)
    print signature[0]
    print signature[1]

@main.command()
@click.option('--message', prompt=True, help='message to be verified')
@click.option('--sign', prompt=True, nargs=2, type=int, help='signature of the message')
@click.option('--key', prompt=True, help='file path of public key of the author')
def verify(message, sign, key):
    """Verify the sign of a message"""
    public_key = load_object(key)
    verified = signature_verification(message, sign, public_key)
    if verified:
        print "Verification Successful!"
    else:
        print "Verification Failed!"

if __name__ == "__main__":
    main()

