from BitVector import *
import sys


class sha512():
    def __init__ (self, inputFile):
        #print("---------- INITIALIZATION ----------")


        # The registers are initialized by the first 64 bits of the fractional
        # parts of the square-roots of the first eight primes. These are
        # shown below in hex:
        h0 = BitVector(hexstring='6a09e667f3bcc908')
        h1 = BitVector(hexstring='bb67ae8584caa73b')
        h2 = BitVector(hexstring='3c6ef372fe94f82b')
        h3 = BitVector(hexstring='a54ff53a5f1d36f1')
        h4 = BitVector(hexstring='510e527fade682d1')
        h5 = BitVector(hexstring='9b05688c2b3e6c1f')
        h6 = BitVector(hexstring='1f83d9abfb41bd6b')
        h7 = BitVector(hexstring='5be0cd19137e2179')
        self.h0 = h0
        self.h1 = h1
        self.h2 = h2
        self.h3 = h3
        self.h4 = h4
        self.h5 = h5
        self.h6 = h6
        self.h7 = h7

        # The K constants (also referred to as the "round constants") are used in round-based processing 
        K = ["428a2f98d728ae22", "7137449123ef65cd", "b5c0fbcfec4d3b2f", "e9b5dba58189dbbc", "3956c25bf348b538", "59f111f1b605d019", "923f82a4af194f9b", "ab1c5ed5da6d8118",
             "d807aa98a3030242", "12835b0145706fbe", "243185be4ee4b28c", "550c7dc3d5ffb4e2", "72be5d74f27b896f", "80deb1fe3b1696b1", "9bdc06a725c71235", "c19bf174cf692694",
             "e49b69c19ef14ad2", "efbe4786384f25e3", "0fc19dc68b8cd5b5", "240ca1cc77ac9c65", "2de92c6f592b0275", "4a7484aa6ea6e483", "5cb0a9dcbd41fbd4", "76f988da831153b5",
             "983e5152ee66dfab", "a831c66d2db43210", "b00327c898fb213f", "bf597fc7beef0ee4", "c6e00bf33da88fc2", "d5a79147930aa725", "06ca6351e003826f", "142929670a0e6e70",
             "27b70a8546d22ffc", "2e1b21385c26c926", "4d2c6dfc5ac42aed", "53380d139d95b3df", "650a73548baf63de", "766a0abb3c77b2a8", "81c2c92e47edaee6", "92722c851482353b",
             "a2bfe8a14cf10364", "a81a664bbc423001", "c24b8b70d0f89791", "c76c51a30654be30", "d192e819d6ef5218", "d69906245565a910", "f40e35855771202a", "106aa07032bbd1b8",
             "19a4c116b8d2d0c8", "1e376c085141ab53", "2748774cdf8eeb99", "34b0bcb5e19b48a8", "391c0cb3c5c95a63", "4ed8aa4ae3418acb", "5b9cca4f7763e373", "682e6ff3d6b2b8a3",
             "748f82ee5defb2fc", "78a5636f43172f60", "84c87814a1f0ab72", "8cc702081a6439ec", "90befffa23631e28", "a4506cebde82bde9", "bef9a3f7b2c67915", "c67178f2e372532b",
             "ca273eceea26619c", "d186b8c721c0c207", "eada7dd6cde0eb1e", "f57d4f7fee6ed178", "06f067aa72176fba", "0a637dc5a2c898a6", "113f9804bef90dae", "1b710b35131c471b",
             "28db77f523047d84", "32caab7b40c72493", "3c9ebe0a15c9bebc", "431d67c49c100d4c", "4cc5d4becb3e42b6", "597f299cfc657e2a", "5fcb6fab3ad6faec", "6c44198c4a475817"]

        # Store constants as bv array
        K_bv = [BitVector(hexstring = k_constant) for k_constant in K]
        self.K_bv = K_bv

        # Setup message bv
        with open(inputFile, 'r') as unhashed_file:
            message = unhashed_file.read()
        bv = BitVector(textstring=message)
        self.bv = bv

        # Set constants
        blockSize = 1024
        wordSize = 64
        rounds = 80
        self.blockSize = blockSize
        self.wordSize = wordSize
        self.rounds = rounds




    def sha512_setup(self, outFile):
        #print("---------- SETUP ----------")
        
        hash_result_bv = self.sha512_algo()
        # achieve a hex version of the binary hash value
        hash_result_hex = hash_result_bv.getHexStringFromBitVector()
        # output to file
        with open(outFile, 'w') as FILEOUT:
            FILEOUT.write(hash_result_hex)





    def sha512_algo(self):
        #print("---------- ALGORITHM ----------")

        ######## STEP 1 ########
        # pad message

        blockSize = self.blockSize #1024
        wordSize = self.wordSize #64
        roundsProcessing = self.rounds #80
        length = self.bv.length()
        bv1 = self.bv + BitVector(bitstring="1")
        length2 = (blockSize - 128)
        length1 = bv1.length()
        howmanyzeros = (length2 - length1) % blockSize
        zerolist = [0] * howmanyzeros
        bv2 = bv1 + BitVector(bitlist = zerolist)
        bv3 = BitVector(intVal = length, size = 128)
        bv4 = bv2 + bv3

        words = [None] * roundsProcessing

        for n in range(0,bv4.length(),blockSize):
            block = bv4[n:n+blockSize]
        
            ######## STEP 2 ########
            # generate the message schedule
            words[0:16] = [block[i:i+wordSize] for i in range(0,blockSize,wordSize)]
            for i in range(16, roundsProcessing):                      
                i_minus_2_word = words[i-2]
                i_minus_15_word = words[i-15]
                sigma0 = (i_minus_15_word.deep_copy() >> 1) ^ (i_minus_15_word.deep_copy() >> 8) ^ \
                                                             (i_minus_15_word.deep_copy().shift_right(7))
                sigma1 = (i_minus_2_word.deep_copy() >> 19) ^ (i_minus_2_word.deep_copy() >> 61) ^ \
                                                             (i_minus_2_word.deep_copy().shift_right(6))
                words[i] = BitVector(intVal=(int(words[i-16]) + int(sigma1) + int(words[i-7]) + \
                                                                      int(sigma0)) & 0xFFFFFFFFFFFFFFFF, size=wordSize)
        
            #  Before we can start STEP 3, we need to store the hash buffer contents obtained from the 
            #  previous input message block in the variables a,b,c,d,e,f,g,h:
            a,b,c,d,e,f,g,h = self.h0,self.h1,self.h2,self.h3,self.h4,self.h5,self.h6,self.h7

            ######## STEP 3 ########
            # apply round-based processing
            for i in range(roundsProcessing):
                ch = (e & f) ^ ((~e) & g)
                maj = (a & b) ^ (a & c) ^ (b & c)
                sum_a = ((a.deep_copy()) >> 28) ^ ((a.deep_copy()) >> 34) ^ ((a.deep_copy()) >> 39)
                sum_e = ((e.deep_copy()) >> 14) ^ ((e.deep_copy()) >> 18) ^ ((e.deep_copy()) >> 41)
                t1 = BitVector(intVal=(int(h) + int(ch) + int(sum_e) + int(words[i]) + int(self.K_bv[i])) & 0xFFFFFFFFFFFFFFFF, size=wordSize)
                t2 = BitVector(intVal=(int(sum_a) + int(maj)) & 0xFFFFFFFFFFFFFFFF, size=wordSize)
                h = g
                g = f
                f = e
                e = BitVector(intVal=(int(d) + int(t1)) & 0xFFFFFFFFFFFFFFFF, size=wordSize)
                d = c
                c = b
                b = a
                a = BitVector(intVal=(int(t1) + int(t2)) & 0xFFFFFFFFFFFFFFFF, size=wordSize)

            ######## STEP 4 ########
            # update hash values for previous message block
            self.h0 = BitVector( intVal = (int(self.h0) + int(a)) & 0xFFFFFFFFFFFFFFFF, size=wordSize )
            self.h1 = BitVector( intVal = (int(self.h1) + int(b)) & 0xFFFFFFFFFFFFFFFF, size=wordSize )
            self.h2 = BitVector( intVal = (int(self.h2) + int(c)) & 0xFFFFFFFFFFFFFFFF, size=wordSize )
            self.h3 = BitVector( intVal = (int(self.h3) + int(d)) & 0xFFFFFFFFFFFFFFFF, size=wordSize )
            self.h4 = BitVector( intVal = (int(self.h4) + int(e)) & 0xFFFFFFFFFFFFFFFF, size=wordSize )
            self.h5 = BitVector( intVal = (int(self.h5) + int(f)) & 0xFFFFFFFFFFFFFFFF, size=wordSize )
            self.h6 = BitVector( intVal = (int(self.h6) + int(g)) & 0xFFFFFFFFFFFFFFFF, size=wordSize )
            self.h7 = BitVector( intVal = (int(self.h7) + int(h)) & 0xFFFFFFFFFFFFFFFF, size=wordSize )

        # concatenate hash buffer contents into a bitvector object
        message_hash = self.h0 + self.h1 + self.h2 + self.h3 + self.h4 + self.h5 + self.h6 + self.h7
        
        return message_hash




if __name__ == '__main__':
    arg_input = sys.argv[1]
    arg_output = sys.argv[2]
    hashObject = sha512(arg_input)
    hashObject.sha512_setup(arg_output)