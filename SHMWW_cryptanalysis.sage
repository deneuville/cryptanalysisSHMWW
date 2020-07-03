import sys
import numpy as np

#Parameters
__PARAMETER_SET__ = 1
__NUMBER_OF_SIGS__ = 1024
__ROOT_FILENAME__ = "PARA-" + str(__PARAMETER_SET__)

#Cryptanalysis parameters
__THRESHOLD__ = 300

"""
  " utility routines :: beginning
"""

# reads a n-dimensional vector from a line
# line is expected to be created by the SHMWW.sage script
def readVect(n, line):
	vect = vector(GF(2), n)
	for i in range(0, n):
		if line[1+3*i] == '1':
			vect[i] = 1

	return vect

# reads a k \times n matrix from the corresponding lines
# line is expected to be created by the SHMWW.sage script
def readMat(k, n, lines):
	mat = matrix(GF(2), k, n)
	for i in range(0, k):
		mat[i] = readVect(n, lines[i+1]) #+1 to ignore '['

	return mat

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

#Returns the Hamming weight of a vector
def hamming_weight(vector):
	weight = 0
	for coordinate in vector:
		weight += int(coordinate)

	return weight

"""
  " utility routines :: end
"""

"""
  " Cryptanalysis routines :: begin
"""

def ISD_try(H, S, column, support, params):
	n, k, nprime, kprime, l, w1, w2, dGV = params
	#Build the system
	subH = H[range(H.nrows()),support]
	subS = S[range(S.nrows()),[column]]

	try:
		solution = subH.solve_right(subS)
	except Exception, err:
		return 0

	E = vector(GF(2), n)

	for i in range(0, len(support)):
		if solution[i][0] == 1:
			E[support[i]] = 1

	return E

#Cryptanalysis function used to recover E
def recoverE(H, S, random_support, maximum_weight, params):
	n, k, nprime, kprime, l, w1, w2, dGV = params
	E = matrix(GF(2), kprime, n)

	#We want to recover E line by line, using the fact that we know which columns are from R
	for line in range(0, kprime):
		while 1:
			#Build a support for the ISD
			support = list(random_support)
			while len(support) < n-k:
				pos = randrange(0, n)
				if pos not in support:
					support.append(pos)

			E_line = ISD_try(H, S, line, support, params)

			if E_line != 0 and hamming_weight(E_line) <= maximum_weight:
				E[line] = E_line
				print "Number of sk recovered lines: %d/%d" % (line, kprime)
				break

	return E


"""
  " Cryptanalysis routines :: end
"""

#Load pk, sk and the signatures
def loadFiles(pkFile, skFile, sigFile, params):
	try:
		f_pk = open(pkFile, "r")
		f_sk = open(skFile, "r")
		f_sig = open(sigFile, "r")
	except Exception, err: 
		print err
		sys.exit(1)

	n, k, nprime, kprime, l, w1, w2, dGV = params

	#Load pk
	pk_lines = f_pk.readlines()
	h_lines = pk_lines[:n-k+2]
	s_lines = pk_lines[n-k+2:]

	H = readMat(n-k, n, h_lines)
	S = readMat(n-k, kprime, s_lines)

	pk = (H, S)

	#Load sk
	E = readMat(kprime, n, f_sk.readlines())
	sk = E

	#Load signatures
	signatures = []
	lines = f_sig.readlines()

	for i in range(0, __NUMBER_OF_SIGS__):
		z = readVect(n, lines[4*i])
		c = readVect(kprime, lines[4*i+1])
		commitment = readVect(n-k, lines[4*i+2])
		signatures.append((z, c, commitment))

	return(pk, sk, signatures)

#Main

def main():
	n, k, nprime, kprime, l, w1, w2, dGV = params = setup(__PARAMETER_SET__)
	#Cryptanalysis example
	(pk, sk, signatures) = loadFiles(__ROOT_FILENAME__ + "pk", __ROOT_FILENAME__ + "sk", __ROOT_FILENAME__ + "sigs", params)

	#Check weights from the E matrix for future verification
	sk_weights = []
	for i in range(0, n):
		weight = 0
		for j in range(0, kprime):
				weight += int(sk[j][i])
		sk_weights.append(weight)

	#First we want to guess the coordinates of high weight in E
	signature_weights = []
	for i in range(0, n):
		weight = 0
		for sig in range(0, __NUMBER_OF_SIGS__):
			weight += int(signatures[sig][0][i])

		signature_weights.append(weight)

	random_columns = []

	for i in range(0, n):
		if signature_weights[i] > __THRESHOLD__:
			random_columns.append(i)

	#In this version we suppose we found every column
	#Now we want to find each line for E using an ISD
	E = recoverE(pk[0], pk[1], random_columns, l*(nprime - kprime), params)

	if E == sk:
		print("Secret key recovered successfully")
	else:
		print("Secret key not recovered")

if __name__ == "__main__":
    main()
