from datetime import time

import tenseal as ts
import random

# 生成 80000 维向量，每个值在 [-1, 1]，保留 5 位小数
vector_80000 = [round(random.uniform(-1, 1), 5) for _ in range(80000)]

# 打印前 10 个数做验证
# print(vector_80000[:10])

# 1. 创建 CKKS 上下文（使用默认参数）
def create_context():
    context = ts.context(
        scheme=ts.SCHEME_TYPE.CKKS,
        poly_modulus_degree=8192,           # 控制加密效率和精度
        coeff_mod_bit_sizes=[60, 40, 40, 60] # CKKS 参数
    )
    context.generate_galois_keys()
    context.global_scale = 2 ** 40
    return context

# 2. 原始十维浮点向量
# plaintext_vector = [3.14, 2.71, 1.41, 0.577, -1.0, 42.0, 6.28, 9.81, -3.14, 0.0]
# print(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
# 3. 创建上下文
context = create_context()

# 4. 加密（向量编码后加密）
# encrypted_vector = ts.ckks_vector(context, plaintext_vector)
encrypted_vector = ts.ckks_vector(context, vector_80000)

# 5. 在加密状态下可以做操作（例如加法、乘法等），这里我们不做任何操作

# 6. 解密
decrypted_vector = encrypted_vector.decrypt()
# print(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
# 7. 打印对比
print("Original Vector:", vector_80000)
print("Decrypted Vector:", decrypted_vector)
