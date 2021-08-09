# Trying out cryptography use Ellyptic Curve Cryptography
# Because this is a test, it should not be used as a real world example.
# The reason is that the way to achieve a random private key is pseudo random and can be predicted.
# For real world implementations, crypto libraries must be used for maximum security.

# Another thing to note is that the hashing algorithm used is SHA3-256 and not Keccak256 like one would in
# a real world implementation with Ethereum. This changes the results if they are to be compared.

# (The reason for this difference is that this program was written in Pythonista on an IPad where installing
# modules is more complicated so the standard library was used)

# Nonetheless, implementing this has been an interesting exercise to help understand Elyptic curve cryptography.

import random
# import hashlib
import math
import sha3
from secp256k1_python import *


# A string of random binary bits is generated 256 times in a string.
# This corresponds to the private key.
def generatePrivateKey():
	pk = ''
	while len(pk) < 256:
		pk += str(random.randint(0,1))
	return pk

# This calculates the corresponding Y coordinate of a given number on the secp256k1 elliptic curve
def findYfromX(x, prime):
	return math.sqrt((x**3 + 7) % prime)


# Given a string, this function converts it first into bits,
# then into a hashed hexadecimal string.
# As mentionned previously, the hashing algorithm used is SHA3-256
def stringToHashedHex(input):	
	pk = input.encode('utf-8')
	m = sha3.keccak_256()
	m.update(pk)
	m = m.hexdigest()
	return m



def generateKeys():
	# Generating the private key and creating a hashed copy in hex format
	privateKeyBits = generatePrivateKey()
	privateKey = stringToHashedHex(privateKeyBits)
	# privateKey = "5582582b73b8140ef44364a727e025cbe167e6a36c94502db868df3097f2ad19"
	# privateKeyBits = bytes.fromhex(privateKey)
	# privateKeyBits = binascii.unhexlify(privateKey)
	# print(privateKeyBits)
	
	# The prime number used here is the prime order of the curve (highest value)
	# We get it with curve.p but it is calculated like this (standard for ethereum)
	# 2**256 -2**32 -2**9 -2**8 -2**7 -2**6 -2**4 -1
	prime = 2**256 -2**32 -2**9 -2**8 -2**7 -2**6 -2**4 -1
	
	# k is the integer value of the private key and y it's corresponding y-coordinate on the elliptic curve 
	k = int(privateKeyBits, 2)
	y = findYfromX(k, prime)
	
	# Verifying that the coordinates belong on the curve here is more of a demonstration than an actual necessity
	verification = (k**3 + 7 - y**2) % prime
	if verification != 0.0:
		print("error during verification")
		return
	
	# To find the public key K, we need to multiply k and G
	# To make it a one way secure computation, we use
	# ellypic curve point multiplication
	# K = k * G
	# result of the multiplication gives two coordinates that need to be hashed (and turned into hex)
	[publicX, publicY] = curve.mul(curve.g, k)
	publicX = stringToHashedHex(str(publicX))
	publicY = stringToHashedHex(str(publicY))
	
	publicKey = '04'  + str(publicX) + str(publicY)
	
	
	hashPublicKey = stringToHashedHex(publicKey)
	address = hashPublicKey[-20:]
	# return

	print("[randomly generated bits for private key:]", privateKeyBits, "\n")	
	print("[keccak256 hashed private key:]", privateKey, "\n")
	print("[big prime number:] ", prime, "\n")
	print("\nPublic Key:")
	print("[x coordinate on the elliptic curve:]", k)
	print("[y coordinate on the elliptic curve:]", round(y), "\n")

	print("[verification:] ", verification == 0.0)	
	
	return privateKey, publicKey, address



print("---------------------------------")

privateKey, publicKey, ethAddress = generateKeys()
# exit()

print("\n---------------------------------")
print("Results:\n")

print("private key:", privateKey)
print("(length:", len(privateKey), ")")
print("")
print("public key:", publicKey)
print("(length:", len(publicKey), ")")
print("")
print("ethereum address:", ethAddress)
print("(length:", len(ethAddress), ")")

print("---------------------------------")
