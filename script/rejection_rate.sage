load ("polygen.sage")
from sage.stats.distributions.discrete_gaussian_integer import DiscreteGaussianDistributionIntegerSampler



n = 512
q = 2^16+1
p = 2
sigma = 107
d = 77
F = P(x^n+1)

D = DiscreteGaussianDistributionIntegerSampler(sigma=sigma)  
r = [D() for _ in range (n)]


################## rejection sampling on keyes #############
def pad_vector(g,n,q):
  g = g+ P(q*x^(n-1))
  g = vector(g)
  g[n-1] = g[n-1] - q
  return g


g = fix_poly_gen(n,d)
N = matrix(n,n)
for i in range (0,n):
  t = g*P(x^i)%P(x^n+1)
  N[i] = pad_vector(t,n,q)

T = N.transpose()*N

################# Firstly, we work on t side ###############


# compute a list of ag and v = r+ag

agnormlist = []
agnorm2= 0
agnorm2list= []
vnormlist = []
maxcount = 10000
for _ in range (maxcount):
  g = fix_poly_gen(n,d)
  a = binary_poly_gen(n)
  r = rnd_poly_gen(n,q) 
  ag = a*g % F
  v = vector(r+ag)
  v = cmod(v,q)
  ag = vector(ag)
  agnormlist.append(ag.norm(infinity))
  vnormlist.append(v.norm(infinity))
  agnorm2list.append(RR(ag.norm(2)))
  if (agnorm2 < ag.norm(2)):
    agnorm2 = ag.norm(2)
  
# find the bound B_t for which the following value is maximized
# Prob(|ag|<B_t) * Prob(r + |ag|)  
Probt = []
for B_t in range (20, 60):
  prob1 = 0
  prob2 = 0
  for i in range (0, maxcount):
    if (agnormlist[i]<B_t):
      prob1 = prob1 +1
      if (vnormlist[i] < q/2-B_t):
        prob2 = prob2 +1      
  print B_t, RR(prob1/maxcount), RR(prob2/maxcount)      
  Probt.append([B_t, RR(prob2/maxcount)] )

# find the optimal B_t
B_t = Prob[0][0]
prob = Prob[0][1]
for i in range (0, 40):  
  if (prob<Probt[i][1]):
    B_t = Probt[i][0]
    prob = Probt[i][1]
print B_t, prob    


#####################################################

################# Now, we work on s side ###############
Probs = []
for i in range(1,20):
  B_s = 100+i*10
  prob = 0
  for i in range (0, maxcount):
    if (agnorm2list[i]<B_s):
      prob = prob+1
  print B_s, RR(prob/maxcount)
  Probs.append([B_s, RR(prob/maxcount)] )

B_s = 215
prob = 0
for i in range (0, maxcount):
  if (agnorm2list[i]<B_s):
    prob = prob+1
print B_s, RR(prob/maxcount)
Probs.append([B_s, RR(prob/maxcount)] )

alpha = sigma/B_s
M = e^(1/2/alpha^2)

print RR(M)
