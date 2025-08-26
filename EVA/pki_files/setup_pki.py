from Cryptodome.PublicKey import ECC
import tenseal as ts
# generate client keys
for i in range (512):
	key = ECC.generate(curve='P-256')
	hdr = 'client'+str(i)+'.pem'
	f = open(hdr, 'wt')
	f.write(key.export_key(format='PEM'))
	f.close()
#
# 生成解密服务器密钥对
key = ECC.generate(curve='P-256')
with open('decryption_server_sk.pem', 'wt') as f:
	f.write(key.export_key(format='PEM'))
with open('decryption_server_pk.pem', 'wt') as f:
	f.write(key.public_key().export_key(format='PEM'))

# PRIVATE_CTX_PATH = "ckks_private.ctx"
# PUBLIC_CTX_PATH = "ckks_public.ctx"
# def create_context():
#     context = ts.context(
#         scheme=ts.SCHEME_TYPE.CKKS,
#         poly_modulus_degree=8192,
#         coeff_mod_bit_sizes=[60, 40, 40, 60]
#     )
#     context.global_scale = 2 ** 40
#     context.generate_galois_keys()
#     return context
#
# def save_contexts(context, pub_path=PUBLIC_CTX_PATH, priv_path=PRIVATE_CTX_PATH):
#     with open(priv_path, "wb") as f:
#         f.write(context.serialize(save_secret_key=True))  # 保存私钥
#
#     public_context = context.copy()
#     public_context.make_context_public()
#     with open(pub_path, "wb") as f:
#         f.write(public_context.serialize())  # 保存公钥
#
# context = create_context()
# save_contexts(context)