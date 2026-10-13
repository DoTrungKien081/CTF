# [WriteUp] ECB

## 1. Phân tích file mã hoá:

```python
import secrets

from Crypto.Cipher import AES

with open("flag.txt", "rb") as f:
    FLAG = f.read().strip()

assert len(FLAG) == 32

def main() -> None:
    key_int = secrets.randbelow(1_000_001) 
    key = key_int.to_bytes(16, "big")

    ct = AES.new(key, AES.MODE_ECB).encrypt(FLAG)
    with open("output.txt", "w") as f:
        f.write(ct.hex())


if __name__ == "__main__":
    main()
```

* File mã hoá sử dụng 2 thư viện là `secrets` và `Crypto` (sử dụng module `AES` cho việc mã hoá).
* **Độ dài Flag:** Dòng 8 đến 11 mở file `flag.txt` và giới hạn `len(FLAG) == 32`. Vì 32 bytes vừa bằng đúng 2 blocks của AES (mỗi block 16 bytes) nên bài toán không cần thực hiện padding.
* **Quá trình sinh Key:** Từ dòng 13 đến dòng 19, biến `key_int` được tạo ngẫu nhiên trong khoảng **[0, 1.000.000]**. Sau đó, `key_int` được chuyển thành chuỗi 16 bytes theo dạng Big-Endian để làm `key` mã hóa AES.
* **Ghi đầu ra:** Ciphertext (`ct`) sau khi mã hóa AES-ECB được chuyển sang dạng chuỗi Hex và ghi vào file `output.txt`.

---

## 2. Hướng giải bài:

* **Lỗi bảo mật (Vulnerability):** Điểm yếu cốt lõi của bài nằm ở **Không gian khóa (Key Space) quá nhỏ**. Ở đây `key_int` chỉ nhận tối đa **1 000 001** giá trị khả thi. Do đó, phương pháp tối ưu và nhanh nhất là **Bruteforce** toàn bộ không gian khóa này.
* **Xử lý Ciphertext:**
  Dữ liệu `ct` thu được dưới dạng Hex ở comment cuối file:
  
  ```python
  # ct: a58fd383d77105ed4cec2ff0eb3e483dea0d8bf2d963ce6e61a7c875a8b4edea
  ```

  Ta cần chuyển đổi `ct` từ chuỗi Hex về dạng `bytes` ban đầu để truyền vào hàm giải mã AES:
  
  ```python
  ct = bytes.fromhex(ct);
  ```

* **Điều kiện nhận dạng:** Flag có tiền tố `W1{` và hậu tố `}`.
* Ý tưởng vòng lặp giải mã:

```python
for key_int in (0..1_000_001):
    key = key_int.to_bytes(16, "big");

    pt = AES.new(key, AES.MODE_ECB).decrypt(ct);
    if (pt.startswith(b"W1{") and pt.endswith(b"}")):
        print(f"{pt}"):
```

---

## 3. Script giải bài:

Ghép tất cả các mảnh lại ta có file `solve.py` hoàn chỉnh:

```python
from Crypto.Cipher import AES

ct = "a58fd383d77105ed4cec2ff0eb3e483dea0d8bf2d963ce6e61a7c875a8b4edea"
ct = bytes.fromhex(ct)

for key_int in range(1_000_001):
    key = key_int.to_bytes(16, "big")
    pt = AES.new(key, AES.MODE_ECB).decrypt(ct)
    if pt.startswith(b"W1{") and pt.endswith(b"}"):
        print(f"{pt}");
```

Chạy file `solve.py`, ta được kết quả:

```text
b'W1{AES_1z_s0_3z_3z_3z_r1ght????}'
```

→ **Flag:** `W1{AES_1z_s0_3z_3z_3z_r1ght????}`
