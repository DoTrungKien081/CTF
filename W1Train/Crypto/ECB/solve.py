from Crypto.Cipher import AES

ct = "a58fd383d77105ed4cec2ff0eb3e483dea0d8bf2d963ce6e61a7c875a8b4edea"
ct = bytes.fromhex(ct)

for key_int in range(1_000_001):
    key = key_int.to_bytes(16, "big")
    pt = AES.new(key, AES.MODE_ECB).decrypt(ct)
    if pt.startswith(b"W1{") and pt.endswith(b"}"):
        print(f"{pt}");
