from fastecdsa.curve import secp256k1
from fastecdsa.keys import export_key, gen_keypair

from fastecdsa import curve, ecdsa, keys, point
from hashlib import sha256

def sign(m):
	''' Your function should return the ECDSA public key and the signature. 
	Recall that an ECDSA signature consists of 2 integers, r,s. T
	These should be returned as a list of length two. Thus your function, “sign,” 
	should return two elements, a public key and a list of length two that holds the two 
	components of the signature. When using the FastECDSA library, you need to specify 
	the elliptic curve and the hash function. Your function should use the curve SECP256K1 
	(the “Bitcoin” curve) and the hash functions SHA256.'''

	#generate public key
	private_key = keys.gen_private_key(curve.secp256k1)
	public_key = keys.get_public_key(private_key, curve.secp256k1)
	
	#generate signature
	#Your code here
	r, s = ecdsa.sign(m, private_key, curve=curve.secp256k1, hashfunc=sha256)
	#valid = ecdsa.verify((r, s), m, public_key, curve=curve.secp256k1, hashfunc=sha256)
	valid = ecdsa.verify((r, s), m, public_key, curve=curve.secp256k1,hashfunc=sha256)

	assert valid
	assert isinstance( public_key, point.Point )
	assert isinstance( r, int )
	assert isinstance( s, int )
	return( public_key, [r,s] )									
