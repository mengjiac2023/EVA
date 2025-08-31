import tenseal as ts
import random
VECTOR_SIZE = 80000
CHUNK_SIZE = 4096
PRIVATE_CTX_PATH = "../ckks_private.ctx"
PUBLIC_CTX_PATH = "../ckks_public.ctx"

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
        ts.ckks_vector(context, [0.0] * chunk.size())
        for chunk in encrypted_chunks
    ]
    return noise_chunks

def rerandomize_ckks_vector(context, encrypted_chunks):
    noise_chunks = [
        ts.ckks_vector(context, [0.0] * chunk.size())
        for chunk in encrypted_chunks
    ]
    return add_encrypted_vectors(encrypted_chunks, noise_chunks)

def add_encrypted_vectors(enc_chunks1, enc_chunks2):
    assert len(enc_chunks1) == len(enc_chunks2), "must equal"
    return [a + b for a, b in zip(enc_chunks1, enc_chunks2)]

def add_multiple_encrypted_vectors(enc_vectors):
    assert len(enc_vectors) > 1, "two item"
    result = enc_vectors[0]
    for enc_vec in enc_vectors[1:]:
        result = add_encrypted_vectors(result, enc_vec)
    return result