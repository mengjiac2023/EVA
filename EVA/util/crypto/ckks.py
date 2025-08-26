import tenseal as ts
import random
VECTOR_SIZE = 80000
CHUNK_SIZE = 4096
PRIVATE_CTX_PATH = "../ckks_private.ctx"
PUBLIC_CTX_PATH = "../ckks_public.ctx"

# ========== 工具函数 ==========
def load_context(path):
    with open(path, "rb") as f:
        return ts.context_from(f.read())

def generate_vector(size):
    return [round(random.uniform(-1, 1), 5) for _ in range(size)]

def encrypt_vector(context, data, chunk_size=CHUNK_SIZE):
    chunks = [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)]
    return [ts.ckks_vector(context, chunk) for chunk in chunks]

def decrypt_vector(private_context, encrypted_chunks):
    rebound_chunks = [ts.ckks_vector_from(private_context, vec.serialize()) for vec in encrypted_chunks]
    decrypted_chunks = [vec.decrypt() for vec in rebound_chunks]
    return [val for chunk in decrypted_chunks for val in chunk]

def noise_ckks_vector(context, encrypted_chunks):
    noise_chunks = [
        ts.ckks_vector(context, [0.0] * chunk.size())  # ⬅️ 使用 .size() 而不是 decrypt()
        for chunk in encrypted_chunks
    ]
    return noise_chunks

def rerandomize_ckks_vector(context, encrypted_chunks):
    noise_chunks = [
        ts.ckks_vector(context, [0.0] * chunk.size())  # ⬅️ 使用 .size() 而不是 decrypt()
        for chunk in encrypted_chunks
    ]
    return add_encrypted_vectors(encrypted_chunks, noise_chunks)

def add_encrypted_vectors(enc_chunks1, enc_chunks2):
    assert len(enc_chunks1) == len(enc_chunks2), "两个密文向量块数必须一致"
    return [a + b for a, b in zip(enc_chunks1, enc_chunks2)]

def add_multiple_encrypted_vectors(enc_vectors):
    # 假设 enc_vectors 中至少有一个元素
    assert len(enc_vectors) > 1, "至少需要两个向量进行加法"
    # 初始化结果为第一个密文向量
    result = enc_vectors[0]
    # 从第二个向量开始逐块加法
    for enc_vec in enc_vectors[1:]:
        result = add_encrypted_vectors(result, enc_vec)  # 使用你之前定义的加法函数
    return result

# Step 2: 生成两个向量
# print("📦 生成两个向量...")
# v1 = generate_vector(VECTOR_SIZE)
# v2 = generate_vector(VECTOR_SIZE)
# plain_sum = [a + b for a, b in zip(v1, v2)]
# # Step 3: 加载公钥 context 并加密
# print("🔐 加载公钥 context 并加密...")
# public_context = load_context(PUBLIC_CTX_PATH)
# enc_v1 = encrypt_vector(public_context, v1)
# enc_v2 = encrypt_vector(public_context, v2)
# enc_v3 = rerandomize_ckks_vector(public_context, enc_v2)
# # Step 4: 密文加法
# print("➕ 密文加法...")
# enc_sum1 = add_multiple_encrypted_vectors([enc_v1, enc_v2])
# enc_sum2 = add_multiple_encrypted_vectors([enc_v1, enc_v3])
# # Step 5: 加载私钥 context 并解密
# print("🔓 加载私钥 context 并解密...")
# private_context = load_context(PRIVATE_CTX_PATH)
# decrypted_sum1 = decrypt_vector(private_context, enc_sum1)
# decrypted_sum2 = decrypt_vector(private_context, enc_sum2)
#
# # Step 6: 验证
# print("\n✅ 验证密文加法是否等于明文加法：")
# print("明文前10项之和: ", [x for x in plain_sum[:10]])
# print("密文加法解密后: ", [x for x in decrypted_sum1[:10]])
# print("密文加法解密后: ", [x for x in decrypted_sum2[:10]])

# # Step 7: 序列化整个带私钥的 context（bytes）
# secret_context_bytes = private_context.serialize(save_secret_key=True)
# hex_secret = secret_context_bytes.hex()
# print("✅ 成功转 context 的序列化内容")
# print(f"私钥 context 序列化大小（字节）: {len(secret_context_bytes)}")
# print(f"转成 hex 字符串长度: {len(hex_secret)}")
# # Step 8: 拆分秘密为60份，阈值20
# shares = PlaintextToHexSecretSharer.split_secret(hex_secret, 20, 60)
#
# # Step 9: 选20份恢复秘密
# selected_shares = random.sample(shares, 20)
#
# print("✅ 成功分解 context 的序列化内容")
# recovered_hex = PlaintextToHexSecretSharer.recover_secret(selected_shares)
#
# assert recovered_hex == hex_secret, "恢复的秘密不一致！"
# print("✅ 成功恢复 context 的序列化内容")
#
# # Step 10: hex转bytes，反序列化恢复 context
# recovered_bytes = binascii.unhexlify(recovered_hex)
# recovered_context = ts.context_from(recovered_bytes)
#
# # Step 11: 用恢复的context解密验证
# decrypted_sum1_recovered = decrypt_vector(recovered_context, enc_sum1)
# print("恢复的context解密前10项:", decrypted_sum1_recovered[:10])

# # Step 1: 将字符串编码为 hex
# hex_secret = PRIVATE_CTX_PATH.encode().hex()
#
# # Step 2: 拆分秘密为60份，阈值为20
# shares = PlaintextToHexSecretSharer.split_secret(hex_secret, 20, 60)
# print(f"🎯 生成了 {len(shares)} 份秘密份额")
#
# # Step 3: 模拟选取任意20份来恢复秘密
# selected_shares = random.sample(shares, 20)
# print("Recovering from shares...")
# result = PlaintextToHexSecretSharer.recover_secret(selected_shares)
# print("Result type:", type(result))
# print("Result value:", result)

# # Step 4: 验证恢复是否一致
# recovered_string = bytes.fromhex(recovered_hex).decode()
# assert recovered_string == PRIVATE_CTX_PATH, "❌ 恢复的秘密不一致！"
#
# print("✅ 成功恢复原始字符串秘密：", recovered_string)
# 要共享的秘密
# secret = "这是一个秘密"
#
# # 分享给的参与者数量（n）和恢复秘密所需的参与者数量（t）
# n = 3  # 总共有3个参与者
# t = 2  # 需要至少2个参与者才能恢复秘密
#
# # 创建秘密共享器
# shares = SecretSharer.split_secret("c4bbcb1fbec99d65bf59d85c8cb62ee2db963f0fe106f483d9afa73bd4e39a8a", 2, 3)
#
#
# # 打印每个参与者的份额
# print("每个参与者的份额:")
# for i, share in enumerate(shares):
#     print(f"参与者 {i+1}: {share}")
#
# # 恢复秘密
# recovered_secret = SecretSharer.recover_secret(shares[0:2])
# print(f"恢复的秘密: {recovered_secret}")
# from secretsharing import HexToHexSecretSharer
#
#
# hex_secret = PRIVATE_CTX_PATH.encode().hex()
# # ✅ Step 1: 拆分秘密为 60 份，阈值 20
# shares = HexToHexSecretSharer.split_secret(hex_secret, 20, 60)
#
# # ✅ Step 2: 从中随机选 20 份恢复
# selected = random.sample(shares, 20)
# recovered_hex = HexToHexSecretSharer.recover_secret(selected)
# print("recovered_hex:",recovered_hex)
# print("hex_secret:",hex_secret)
# # ✅ Step 3: 验证是否恢复正确
# assert recovered_hex == hex_secret
# print("✅ Secret 恢复成功！")
# recovered_path = bytes.fromhex(recovered_hex).decode()
# print("恢复后的 PRIVATE_CTX_PATH:", recovered_path)