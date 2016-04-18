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

# There's 3 nice ways to enter the public key: as octet string (if you'd want to use this for attacking something that reads a certificate), as binary string, and as integers:

# publickey = publickey_from_octetstring(curve, "04:01:cd:...")
# publickey = get_publickey(curve, 0b101010100... (x coordinate), 0b10111111... (y coordinate))
# publickey = get_publickey(curve, 95394827547... (x coordinate), 8320640249... (y coordinate))

# But we're just going to read it (decimally) from a file:
with open("publickey", "r") as publickey_file:
  content = publickey_file.read()
  x, y = content.split(",")
  publickey = get_publickey(curve, int(x), int(y))

@parallel
def try_it(subset):
  r, private = get_result(F, subset, fixed_order)
  print "Computed the private key as: %s" % str(private)
  correct = is_private_key_correct(generator, publickey, private)
  if correct:
    print "... FOUND IT! private key is %s!" % str(private)
    print "... you can Ctrl+C now to stop the computation"
  else:
    print "... but it was not the correct private key, continuing to search"

def find_private():
  # The input format is message (digest), r, s, time
  inputs = []
  for (m, sig_r,sig_s,time) in data:
    # If you'd ever need to manually truncate the digest to the right number of bits: m = int(m) >> (512 - 163)
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
