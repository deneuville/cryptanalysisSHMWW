import sys
import numpy as np # used for generating permutations

__PARAMETER_SET__ = 1
__NUMBER_OF_SIGS__ = 1024
__ROOT_FILENAME__ = "PARA"+str(__PARAMETER_SET__)+"bis_"
__MANUAL_SETUP__ = 1 # Change to 1 to specify the instance, filename, and number of signatures to generate 
__VERBOSE__ = 0 # Change to 0 when done cryptanalysing

"""
  " utility routines :: beginning
"""

# stores a n-dimensional vector v into file f
# (f is assumed opened in write format)
def storeVect(n , v, f):
	for i in xrange(n-1):
		f.write("%d, " % v[i])
	f.write("%d" % v[n-1])

# stores a (k,n)-matrix M into file filename
def storeMat(k, n , M, f):
	f.write("[\n")
	for i in xrange(k):
		f.write("[")
		storeVect(n, M[i], f)
		f.write("]\n")
	f.write("]\n")

# opens a file in write mode and returns the pointer to that file 
def openFile(filename):
	try:
		f = open(filename, "w")
	except Exception, err: 
		print err
		sys.exit(1)
	return f

# returns a random word of length n and weight w
def generateRandomWordWithSpecificLengthAndWeigh(n, w):
	weight = 0
	v = vector(GF(2), n)
	while (weight < w):
		index = randint(0, n-1)
		if (v[index] == 0):
			v[index] = 1
			weight += 1
	return v

"""
  " utility routines :: end
"""


"""
  " SHMWW signature scheme :: beginning
"""

# returns a parameter set from SHMWW, either para-1, or para-2
def setup(instance=1):
	if (instance==1):
		n=4096
		k=539
		dGV=1191
		l=4
		nprime=1024
		kprime=890
		w1=31
		w2=531
		secu=80
	elif (instance==2):
		n=8192
		k=1065
		dGV=2383
		l=8
		nprime=1024
		kprime=880
		w1=53
		w2=807
		secu=128
	else :
		print "Parameter set undefined, check SHMWW"
		n = k = nprime = kprime = l = w1 = w2 = dGV = 0
	return n, k, nprime, kprime, l, w1, w2, dGV

# given the parameters returned by setup, generates the public and secret keys
def KeyGen(params): 
	n, k, nprime, kprime, l, w1, w2, dGV = params
	H = random_matrix(GF(2), n-k, n)

	# generate E' = [Ik'|R1 | ... | Ik'|Rl]
	Ikp = identity_matrix(GF(2), kprime)
	Eprime=matrix(GF(2), kprime, 0)
	for i in range(l):
		Ri = random_matrix(GF(2), kprime, nprime-kprime)
		Eprime = block_matrix([[Eprime, Ikp, Ri]])

	# generate P1 (k' x k' perm. matrix)
	p1 = np.random.permutation(int(kprime))
	P1 = matrix(GF(2), kprime)
	for i in range(kprime):
		P1[i] = Ikp[p1[i]]

	# generate P2 (n x n perm. matrix)
	In = identity_matrix(GF(2), n)
	p2 = np.random.permutation(int(n))
	P2 = matrix(GF(2), n)
	for i in range(n):
		P2[i] = In[p2[i]]

	E = P1 * Eprime * P2
	S = H * E.transpose()

	pk = (H, S)
	sk = E

	return pk, sk

# returns a signature that will pass the verification step
# /!\ IMPORTANT_WARNING: no Weight Restricted Hash (WRH) function is used.
# For cryptanalytic purposes, we only need a random vector a weight w1 and length k'
# A WRH is fully described in SHMWW, and can be plugged in if needed.
# Integrating a WRH function can only slow down the execution, not prevent the leak. 
def Sign(params, pk, sk):
	n, k, nprime, kprime, l, w1, w2, dGV = params
	H, S = pk
	E = sk
	c = generateRandomWordWithSpecificLengthAndWeigh(kprime, w1)
	e = generateRandomWordWithSpecificLengthAndWeigh(n, w2)
	commitment = H*e
	z = c*E + e
	return (z, c, commitment)


# this is pointless for cryptanalysis' purposes but why not...
def Verify(params, sig, pk):
	n, k, nprime, kprime, l, w1, w2, dGV = params
	z, c, commitment = sig
	H, S = pk
	if z.hamming_weight() > dGV:
		print "z too large\n"
		return 1
	if H*z- S*c != commitment:
		print "Signature different from commited value"	
		return 2
	return 0

"""
  " SHMWW signature scheme :: end
"""

""" ########
  " # MAIN #
""" ########
def main():
	root_filename = __ROOT_FILENAME__
	nb_sigs = __NUMBER_OF_SIGS__

	if __MANUAL_SETUP__ == 1:
		root_filename = raw_input("Enter filename [default=PARA1_{pk, sk, sigs}]: ") or __ROOT_FILENAME__
		nb_sigs = int(raw_input("Enter the number of desired signatures[1024]: ") or __NUMBER_OF_SIGS__)

	if __VERBOSE__ == 1:
		print "Selecting parameters from set PARA-%d." % __PARAMETER_SET__
	n, k, nprime, kprime, l, w1, w2, dGV = params = setup(__PARAMETER_SET__)
	if __VERBOSE__ == 1:
		print "Selected parameters : "
		print "n = %d, k = %d, nprime = %d, kprime = %d, l = %d, w1 = %d, w2 = %d, dGV = %d" % (n, k, nprime, kprime, l, w1, w2, dGV)

	if __VERBOSE__ == 1:
		print "Generating keys"
	pk, sk = KeyGen(params)
	if __VERBOSE__ == 1:
		print "pk and sk succesfully generated"

	pk_filename = root_filename + "pk"
	if __VERBOSE__ == 1:
		print "Storing pk in file: %s." % (pk_filename)
	f = openFile(pk_filename)
	storeMat(n-k, n, pk[0], f)
	if __VERBOSE__ == 1:
		print "H = pk[0] stored succesfully, storing S = pk[1]."
	storeMat(n-k, kprime, pk[1], f)
	if __VERBOSE__ == 1:
		print "S = pk[1] stored succesfully."
	f.close()

	sk_filename = root_filename + "sk"
	if __VERBOSE__ == 1:
		print "Storing sk in file: %s." % (sk_filename)
	f = openFile(sk_filename)
	storeMat(kprime, n, sk, f)
	if __VERBOSE__ == 1:
		print "sk stored succesfully."
	f.close()

	sigs_filename = root_filename + "sigs"
	if __VERBOSE__ == 1:
		print "Generating and storing %d signatures in file: %s." % (nb_sigs, sigs_filename)
	f = openFile(sigs_filename)
	for i in range(nb_sigs):
		if __VERBOSE__ == 1:
			print "Generating signature %d out of %d " % (i+1, nb_sigs)
		sig = Sign(params, pk, sk)
		if __VERBOSE__ == 1:
			print "Signature %d generated succesfully." % (i+1)
			print "Now verifying it..."
		if Verify(params, sig, pk) != 0:
			if __VERBOSE__ == 1:
				print "Signature verification failed, aborting"
			f.close()
			sys.exit(1)
		else:
			if __VERBOSE__ == 1:
				print "Passed verification!"
		if __VERBOSE__ == 1:
			print "Storing %d generated succesfully." % (i+1)
		z, c, commitment = sig
		f.write("[")
		storeVect(n, z, f)
		f.write("]\n")
		f.write("[")
		storeVect(kprime, c, f)
		f.write("]\n")
		f.write("[")
		storeVect(n - k, commitment, f)
		f.write("]\n\n")
	f.close()





