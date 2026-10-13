# [WriteUp] RSA - Hastad's Broadcast Attack

## 1. Phân tích file mã hoá:

```python
#!/usr/bin/env python3

from Crypto.Util.number import bytes_to_long, getPrime
from secret import messages


def RSA_encrypt(message):
    m = bytes_to_long(message)
    p = getPrime(1024)
    q = getPrime(1024)
    N = p * q
    e = 3
    c = pow(m, e, N)
    return N, e, c


for m in messages:
    N, e, c = RSA_encrypt(m)
    print(f"n = {N}")
    print(f"e = {e}")
    print(f"c = {c}")
```

* **Cấu hình RSA:** Thuật toán mã hóa RSA sử dụng số mũ công khai rất nhỏ `e = 3` và sinh các cặp số nguyên tố 1024-bit (`p`, `q`) ngẫu nhiên cho mỗi lần mã hóa.
* **Tập dữ liệu:** Đề bài thực hiện mã hóa danh sách các thông điệp `messages` và xuất ra 7 cặp khóa công khai cùng ciphertext `(nᵢ, e, cᵢ)` tương ứng trong file `output.txt`.
* **Lỗ hổng:** Thông điệp được mã hóa trực tiếp mà không sử dụng padding

---

## 2. Hướng giải bài:

* **Hastad's Broadcast Attack:** 
  Khi cùng một thông điệp `m` được mã hóa `k` lần bằng số mũ công khai `e` nhỏ với các modulo `N₁, N₂, ..., Nₖ` đôi một nguyên tố cùng nhau, nếu `k >= e` (ở đây `e = 3` và ta có tới 7 cặp ciphertext), bài toán rơi vào kịch bản tấn công **Hastad's Broadcast Attack** kết hợp **Định lý Thặng dư Trung Hoa (Chinese Remainder Theorem - CRT)**.

* **Cơ sở toán học:**
  Xét 3 cặp `(Nᵢ, cᵢ)` mã hóa cùng một thông điệp `m`:
  
  > c₁ ≡ m³ (mod N₁)<br>
  > c₂ ≡ m³ (mod N₂)<br>
  > c₃ ≡ m³ (mod N₃)

  Áp dụng CRT, ta tìm được giá trị `C` thỏa mãn:
  
  > C ≡ m³ (mod N₁ × N₂ × N₃)

  Do `m < Nᵢ` ⇒ `m³ < N₁ × N₂ × N₃`, phép đồng dư trở thành **phép bằng trên tập số nguyên**:
  
  > C = m³

  Lúc này, chỉ cần lấy căn bậc 3 trực tiếp của `C` trên tập số nguyên là thu lại được thông điệp ban đầu `m`.

* **Xử lý tập dữ liệu:** Do file `output.txt` chứa 7 bản mã, ta chỉ cần quét các tổ hợp 3 bản mã để lọc ra các ciphertext mã hóa cùng một thông điệp.

---

## 3. Script giải bài:

Tạo file `solve.py` sử dụng `sympy` để giải:

```python
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
        break
```

---

## 4. Kết quả:

Chạy file `solve.py`, ta thu được thông điệp hoàn chỉnh chứa Flag:

```text
yes

---

Johan Hastad
Professor in Computer Science in the Theoretical Computer Science
Group at the School of Computer Science and Communication at KTH Royal Institute of Technology in Stockholm, Sweden.

crypto{1f_y0u_d0nt_p4d_y0u_4r3_Vuln3rabl3}
```

⇒ **Flag:** `crypto{1f_y0u_d0nt_p4d_y0u_4r3_Vuln3rabl3}`
