from itertools import combinations
from sympy.ntheory.modular import crt
from sympy import integer_nthroot
from Crypto.Util.number import long_to_bytes

N_list = []
c_list = []

with open("output.txt", "r") as f:
    for line in f:
        if line.startswith("n = "):
            N_list.append(int(line.split(" = ")[1].strip()))
        elif line.startswith("c = "):
            c_list.append(int(line.split(" = ")[1].strip()))

for set3 in combinations(range(len(N_list)), 3):
    N_sub = [N_list[i] for i in set3]
    c_sub = [c_list[i] for i in set3]

    val, _ = crt(N_sub, c_sub)
    m, exact = integer_nthroot(val, 3)

    if exact:
        print(f"{long_to_bytes(m).decode()}")
