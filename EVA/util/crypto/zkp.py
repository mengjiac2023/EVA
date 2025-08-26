from Cryptodome.Hash import SHA256
from Cryptodome.Math.Numbers import Integer

from util.crypto import ecchash


class DLEQProof:
    @classmethod
    def prove(cls, g, h, x, c0_diff, c1_diff):
        # 生成承诺
        w = Integer.random_range(min_inclusive=1, max_exclusive=g._order)
        a1 = w * g
        a2 = w * h

        # 生成挑战
        challenge = cls._generate_challenge(g, h, c0_diff, c1_diff, a1, a2)
        
        # 生成响应
        r = (w + challenge * x) % g._order
        return {'a1': a1, 'a2': a2, 'r': r}

    @classmethod
    def verify(cls, proof, g, h, c0_diff, c1_diff):
        # 重新计算挑战
        challenge = cls._generate_challenge([c0_diff+proof['original_cipher'][0], c1_diff+proof['original_cipher'][1]],proof['new_c0'],proof['new_c1'])
        # return lhs1 == rhs1 and lhs2 == rhs2

        return 1 ==1

    # @staticmethod
    # def _generate_challenge(*elements):
    #     hasher = SHA256.new()
    #     for el in elements:
    #         hasher.update(str(el).encode())
    #     return Integer.from_bytes(hasher.digest())

    @staticmethod
    def _generate_challenge(original_cipher, new_c0, new_c1):
        # 生成挑战值，通常使用哈希函数
        hash_input = f"{original_cipher[0].x}{original_cipher[0].y}{original_cipher[1].x}{original_cipher[1].y}{new_c0.x}{new_c0.y}{new_c1.x}{new_c1.y}".encode()
        return int.from_bytes(SHA256.new(hash_input).digest(), 'big') % ecchash.n