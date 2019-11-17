
"""
# TODO: make description

"""
import math
import numpy
import sys

numpy.set_printoptions(threshold=sys.maxsize)  #to print full NumPy arrays, without truncation
dmin = 50

def run(file):
    with open(file, 'r') as f:
        M0 = [int(line.strip()) for line in f]  # removes new line char ('\n') with strip and converts strings to int values
        L0 = len(M0)
        print('len M0 = ', L0)
        OptN = periods(L0)
        D = divisors(OptN, dmin)

        M = M0[0:OptN]
        print('len M = ', len(M))
        L = len(D)
        RSn = []
        for i in range(0, L):
            A = OptN // D[i]  #integer dividing
            # print('M len = ', len(M))
            # print('M0 = ', M[0])
            # print('M last = ', M[len(M)-1])
            # print('D[i] = ', D[i])
            # print('A = ', A)
            """
            reshape array column-wise, like
            input array: [0, 1, 2, 3]
            output matrix (with F option):
            [[0 2]
            [1 3]]
            output matrix (without F option):
            [[0 1]
            [2 3]]
            """
            N = numpy.reshape(M, (D[i], A), order='F')
            # print('reshaped N: ')
            # print(N)
            e = numpy.mean(N, axis = 0)
            S = numpy.std(N, axis = 0)
            for j in range(0, A):
                N[:, j] = N[:, j] - e[j]  #perform operation for j-th column of matrix
            cumsum = numpy.cumsum(N, axis=0) #cumsum over rows for each of the columns
            R = numpy.amax(cumsum, axis=0) - numpy.amin(cumsum, axis=0)  #array subtract array
            RS = numpy.divide(R, S)  #array divides array
            RSn.append(numpy.mean(RS))
        print('D = ', D)
        print('RSn = ', RSn)
        logD = numpy.log10(D)
        logRSn = numpy.log10(RSn)
        P = numpy.polyfit(logD, logRSn, 1)
        print('P - ', P)
        H = P[0]
        print('H - ', H)

def periods(L):
    L0 = math.floor(0.99*L)
    dv = []
    for i in range(L0, L):
        dv.append(len(divisors(i, dmin)))
    print('dv: ', *dv)
    maximum = max(dv)
    # print('max = ', maximum)
    # print('index = ', dv.index(maximum))
    OptN = L0 + dv.index(maximum) #remove '-1' because of indexes in python starting from 0
    print('OptN = ', OptN)
    return OptN


# Find all divisors of the natural number N greater or equal to N0
def divisors(n, n0):
    d = []
    for i in range(n0, math.floor(n/2)+1):
        if (n/i == math.floor(n/i)):
            d.append(i)
    return d

def test_arrays():
    A = numpy.array([[0,3],[1,4],[2,5]])
    print(A)
    for j in range(0, 2):
        print(A[:,j])


# if __name__ == '__main__':
#     log_file = open("logger.log","w")
#     sys.stdout = log_file
#     main()
#     log_file.close()
#     # test_arrays()
