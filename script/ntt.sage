q = 2^16+1
P.<x> = PolynomialRing(Zmod(q))
F = P(x^512+1)
r = F.roots()
M = matrix(512,512)
for i in range (0,512):
  for j in range (0,512):
    M[i,j] = (r[511-i][0])^j  

M = M.change_ring(Zmod(q))
N = M.inverse()
N = N.change_ring(ZZ)
f = open("ntt.txt", "w")

f.write("{") 
for i in range (0,512):
  f.write("{")
  for j in range (0,512):
    f.write((N[i,j]).str())
    if (j!=512):
      f.write(",")
    if (j%16==15):
      f.write("\n")
  f.write("},\n")
f.write("}")
f.close()    
        
