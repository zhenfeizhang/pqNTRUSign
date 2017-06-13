
P.<x> = PolynomialRing(ZZ)


##################################

def fix_poly_gen(n,d):
  a = P(1)
  i = 0
  while (i<d):
    index = ZZ.random_element(1,n) 
    if (a[index] == 0):
      a = a + P(x^index)
      i = i + 1
  i = 0    
  while (i<d):    
    index = ZZ.random_element(1,n)   
    if (a[index] == 0):
      a = a - P(x^index)
      i = i + 1  
  
  return a
  
##################################  
def inverse_poly_gen (n, d, q, F):  
  f = poly_gen(n,d)
  a,b,c = xgcd (f, F)
  while (gcd(ZZ(a),q)!=1):
    f = poly_gen(n,d)
    a,b,c = xgcd (f, F)

  a_inv = 1/ZZ(a)%q
  f_inv = b*a_inv%q
  
  return f, f_inv   
  
##################################    
def check_inverse (f, q, F):
  a,b,c = xgcd (f, F)
  f_inv = P(0)
  if (gcd(ZZ(a),q)==1):
    a_inv = 1/ZZ(a)%q
    f_inv = b*a_inv%q
  return f_inv    
  
##################################
def tri_poly_gen(n):
  a = (Zmod(3)^n).random_element()
  a = a.change_ring(ZZ)
  for j in range (0, N):
    a[j] = a[j]-1
  a = P(a.list())
  return a  
##################################
def binary_poly_gen(n):
  a = (Zmod(2)^n).random_element()
  a = a.change_ring(ZZ)
  a = P(a.list())
  return a    
##################################
def rnd_poly_gen(n,q):
  f = (Zmod(q)^n).random_element()
  f = f.change_ring(ZZ)
  for j in range (0, n):
    f[j] = f[j]-round(q/2)
  f = P(f.list())  
  return f
##################################
def sparse_mat(n,m, d):
  mat = matrix(n,m)
  for i in range (0, n):
    j = 0
    while (j<=d):
      index = ZZ.random_element(0,m) 
      if (mat[i,index] == 0):
        mat[i,index] = 1
        j = j + 1
    j = 0    
    while (j<d):    
      index = ZZ.random_element(0,m)   
      if (mat[i,index] == 0):
        mat[i,index] = -1
        j = j + 1
  
  return mat
###################################
##################################
def sparse_bal_mat(n,m, d):
  mat = matrix(n,m)
  for i in range (0, n):
    j = 0
    while (j<d):
      index = ZZ.random_element(0,m) 
      if (mat[i,index] == 0):
        mat[i,index] = 1
        j = j + 1
    j = 0    
    while (j<d):    
      index = ZZ.random_element(0,m)   
      if (mat[i,index] == 0):
        mat[i,index] = -1
        j = j + 1
  
  return mat  
  
  
###############################
def cmod(f,q):
  for i in range (f.degree()):
    f[i] = f[i]%q
    if (f[i] > q/2):
      f[i] = f[i]-q
  return f      
  
sigma = 256
from sage.stats.distributions.discrete_gaussian_integer import DiscreteGaussianDistributionIntegerSampler

D = DiscreteGaussianDistributionIntegerSampler(sigma=sigma)  
    
