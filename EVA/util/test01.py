import time
import random
import tenseal as ts

# 生成 80000 维向量，每个值在 [-1, 1]，保留 5 位小数
vector_80000 = [round(random.uniform(-1, 1), 5) for _ in range(80000)]

# 创建 CKKS 上下文
def create_context():
    context = ts.context(
        scheme=ts.SCHEME_TYPE.CKKS,
        poly_modulus_degree=8192,
        coeff_mod_bit_sizes=[60, 40, 40, 60]
    )
    context.generate_galois_keys()
    context.global_scale = 2 ** 40
    return context

context = create_context()

print("Start encryption at:", time.strftime("%Y-%m-%d %H:%M:%S"))

# 分块加密
chunk_size = 4096
chunks = [vector_80000[i:i + chunk_size] for i in range(0, len(vector_80000), chunk_size)]
encrypted_chunks = [ts.ckks_vector(context, chunk) for chunk in chunks]

# 解密
decrypted_chunks = [vec.decrypt() for vec in encrypted_chunks]
decrypted_vector = [val for chunk in decrypted_chunks for val in chunk]

print("Finish decryption at:", time.strftime("%Y-%m-%d %H:%M:%S"))
print("First 10 original:", vector_80000[:10])
print("First 10 decrypted:", decrypted_vector[:10])

# ========== 配置 ==========
VECTOR_SIZE = 80000
CHUNK_SIZE = 4096
PRIVATE_CTX_PATH = "ckks_private.ctx"
PUBLIC_CTX_PATH = "ckks_public.ctx"

# ========== 工具函数 ==========

def create_context():
    context = ts.context(
        scheme=ts.SCHEME_TYPE.CKKS,
        poly_modulus_degree=8192,
        coeff_mod_bit_sizes=[60, 40, 40, 60]
    )
    context.global_scale = 2 ** 40
    context.generate_galois_keys()
    return context

def save_contexts(context, pub_path=PUBLIC_CTX_PATH, priv_path=PRIVATE_CTX_PATH):
    with open(priv_path, "wb") as f:
        f.write(context.serialize(save_secret_key=True))  # 保存私钥

    public_context = context.copy()
    public_context.make_context_public()
    with open(pub_path, "wb") as f:
        f.write(public_context.serialize())  # 保存公钥

def load_context(path):
    with open(path, "rb") as f:
        return ts.context_from(f.read())

def generate_vector(size):
    return [round(random.uniform(-1, 1), 5) for _ in range(size)]

def encrypt_vector(context, data, chunk_size=CHUNK_SIZE):
    chunks = [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)]
    return [ts.ckks_vector(context, chunk) for chunk in chunks]

def rebind_encrypted_chunks(encrypted_chunks, new_context):
    return [ts.ckks_vector_from(new_context, vec.serialize()) for vec in encrypted_chunks]

def decrypt_vector(private_context, encrypted_chunks):
    rebound_chunks = [ts.ckks_vector_from(private_context, vec.serialize()) for vec in encrypted_chunks]
    decrypted_chunks = [vec.decrypt() for vec in rebound_chunks]
    return [val for chunk in decrypted_chunks for val in chunk]
# ========== 主流程 ==========

# Step 1: 创建上下文并保存
print("🛠️ 创建 context 并保存到磁盘...")
context = create_context()
save_contexts(context)

# Step 2: 生成向量
print("📦 生成加密数据...")
original_vector = generate_vector(VECTOR_SIZE)

# Step 3: 加载公钥 context 进行加密
print("🔐 加载公钥 context 并加密...")
public_context = load_context(PUBLIC_CTX_PATH)
encrypted_chunks = encrypt_vector(public_context, original_vector)

# Step 4: 加载私钥 context 并解密（注意重新绑定）
print("🔓 加载私钥 context 并解密...")
private_context = load_context(PRIVATE_CTX_PATH)
# 解密
decrypted_vector = decrypt_vector(private_context, encrypted_chunks)

# Step 5: 验证结果
print("\n✅ 验证结果：")
print("前10个原始值:", original_vector[:10])
print("前10个解密值:", decrypted_vector[:10])
print("前10个原始值:", original_vector[-1])
print("前10个解密值:", decrypted_vector[-1])