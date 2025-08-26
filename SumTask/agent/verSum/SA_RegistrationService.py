import dill
from Cryptodome.Hash import SHA256
import pandas as pd
from agent.Agent import Agent
from message.Message import Message


class SA_RegistrationService(Agent):
    def __init__(self, id, name, type,
                 iterations=5, random_state=None,):
        super().__init__(id, name, type, random_state)
        self.private_board = {}  # {cipher_id: original_cipher}
        self.public_board = {}  # {cipher_id: (rerand_cipher, zkp)}
        self.cipher_registry = {}  # 新增注册记录存储
        self.no_of_iterations = iterations
        self.elapsed_time = {'REPORT': pd.Timedelta(0)}

    def kernelStarting(self, startTime):
        # self.kernel is set in Agent.kernelInitializing()

        # Initialize custom state properties into which we will accumulate results later.
        self.kernel.custom_state['rs_report'] = pd.Timedelta(0)

        # This agent should have negligible (or no) computation delay until otherwise specified.
        self.setComputationDelay(0)

        # Request a wake-up call as in the base Agent.
        super().kernelStarting(startTime)

    def kernelStopping(self):
        # Add the server time components to the custom state in the Kernel, for output to the config.
        # Note that times which should be reported in the mean per iteration are already so computed.
        self.kernel.custom_state['rs_report'] += (
            self.elapsed_time['REPORT'] / self.no_of_iterations)


        # Allow the base class to perform stopping activities.
        super().kernelStopping()

    def ckks_cipher_list_to_bytes(self, cipher_list):
        data = b""
        for vec in cipher_list:
            serialized = vec.serialize()  # 返回 bytes 类型
            data += serialized
        return data

    def registerCipher(self, cipherList, truncate=1):
        # cipherList 是 CKKSVector 列表
        data = self.ckks_cipher_list_to_bytes(cipherList[:truncate])
        cipher_hash = SHA256.new(data).digest()
        cipher_id = int.from_bytes(cipher_hash[:4], 'big')  # 截断长度可调
        return cipher_id

    def receiveMessage(self, currentTime, msg):
        super().receiveMessage(currentTime, msg)
        """处理来自收集服务器的注册请求"""
        if msg.body.get('msg') == "REGISTER":
            # 从消息中提取密文列表
            cipher_list = msg.body['cipher']

            # 生成注册ID
            cipher_id = self.registerCipher(cipher_list)

            # 存储原始密文到私有公告板
            self.private_board[cipher_id] = cipher_list

            # 返回注册响应
            self.sendMessage(msg.body['sender'], Message({
                "msg": "REGISTER_RESPONSE",
                "cipher_id": cipher_id,
                "client_id": msg.body['client_id'],
                "sender": self.id,
            }))
        if msg.body.get('msg') == "REGISTER_BATCH":
            """
            msg.body['cipher_batch'] 应该是一个列表，每项是：
            { 'client_id': X, 'cipher': [CKKSVector, ...] }
            """

            cipher_batch = msg.body['cipher_batch']
            response_list = []

            for item in cipher_batch:
                client_id = item['client_id']
                cipher_list = item['cipher']

                cipher_id = self.registerCipher(cipher_list)

                # 存储原始密文到私有公告板
                self.private_board[cipher_id] = cipher_list

                response_list.append({
                    "client_id": client_id,
                    "cipher_id": cipher_id
                })

            # 批量响应
            self.sendMessage(msg.body['sender'], Message({
                "msg": "REGISTER_RESPONSE_BATCH",
                "responses": response_list,
                "sender": self.id,
            }))
    # ... 保留现有的ecc_point_list_to_bytes和registerCipher方法 ...
