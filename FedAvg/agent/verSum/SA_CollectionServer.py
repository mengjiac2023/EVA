import os

import numpy as np
import pandas as pd
from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import ECC
from Cryptodome.Random import get_random_bytes

from agent.Agent import Agent
from message.Message import Message
from util import param
from util.crypto import ecchash
from util.crypto import ckks


class SA_CollectionServer(Agent):
    # 类常量定义路径
    DEFAULT_PK_PATH = os.path.normpath(
        os.path.join(os.path.dirname(__file__), '../../pki_files/ckks_public.ctx')
    )
    def __init__(self, reg_service_id, id, name, type,
                 random_state,
                 client_num,
                 iterations,
                 decryption_pk_path=DEFAULT_PK_PATH):
        super().__init__(id, name, type, random_state)

        self.reg_service_id = reg_service_id  # 注册服务ID
        self.public_board = {}  # 在初始化时添加公告板存储
        self.private_board = {}  # 在初始化时添加公告板存储
        # self.cipher_buffer = {}  # 新增：用于暂存收集的密文 {client_id: cipher}
        # self.expected_clients = 10  # 预设的参与方数量，根据实际情况调整
        self.client_num = client_num
        self.rerand_cipher = {}
        # 加载公钥
        self.public_context = ckks.load_context(decryption_pk_path)

        self.cipher_registry = {}  # {client_id: cipher_id}
        self.pending_clients = {}  # {client_id: cipherList} 用于暂存等待注册的客户端
        self.user_vectors = {}
        self.no_of_iterations = iterations
        # Track the current iteration and round of the protocol.
        self.current_iteration = 1
        self.current_round = 0

        # Map the message processing functions
        self.aggProcessingMap = {
            0: self.initFunc,
            1: self.report,
        }

        self.namedict = {
            0: "init",
            1: "report",
        }

        # agent accumulation of elapsed times by category of tasks
        self.elapsed_time = {'REPORT': pd.Timedelta(0),
                             'RERANDOMIZE': pd.Timedelta(0)
                             }
    # Simulation lifecycle messages.

    def kernelStarting(self, startTime):
        # self.kernel is set in Agent.kernelInitializing()

        # Initialize custom state properties into which we will accumulate results later.
        self.kernel.custom_state['cs_report'] = pd.Timedelta(0)
        self.kernel.custom_state['cs_rerandomize'] = pd.Timedelta(0)

        # This agent should have negligible (or no) computation delay until otherwise specified.
        self.setComputationDelay(0)

        # Request a wake-up call as in the base Agent.
        super().kernelStarting(startTime)

    def kernelStopping(self):
        # Add the server time components to the custom state in the Kernel, for output to the config.
        # Note that times which should be reported in the mean per iteration are already so computed.
        self.kernel.custom_state['cs_report'] += (
            self.elapsed_time['REPORT'] / self.no_of_iterations)
        self.kernel.custom_state['cs_rerandomize'] += (
            self.elapsed_time['RERANDOMIZE'] / self.no_of_iterations)

        # Allow the base class to perform stopping activities.
        super().kernelStopping()


    def wakeup(self, currentTime):
        super().wakeup(currentTime)
        print(f"[CS] wakeup in iteration {self.current_iteration} at function {self.namedict[self.current_round]}; current time is {currentTime}")

        # In the k-th iteration
        self.aggProcessingMap[self.current_round](currentTime)

    def initFunc(self, currentTime):
        dt_protocol_start = pd.Timestamp('now')
        self.current_round = 1
        server_comp_delay = pd.Timestamp('now') - dt_protocol_start
        self.setWakeup(currentTime + server_comp_delay + param.wt_versum_report)

    def report(self,currentTime):
        dt_protocol_start = pd.Timestamp('now')
        self.user_vectors = self.pending_clients
        self.pending_clients = {}
        print("[CS] number of collected vectors:", len(self.user_vectors))
        self.rerandom(currentTime)
        server_comp_delay = pd.Timestamp('now') - dt_protocol_start
        print("[CS] run time for report step:", server_comp_delay)
        # Accumulate into time log.
        self.recordTime(dt_protocol_start, "REPORT")
        self.current_round = 1
        # self.setWakeup(currentTime + server_comp_delay + param.wt_versum_rerandomize)

    def rerandom(self,currentTime):
        if not self.user_vectors:
            print("[CS] Skip rerandomize: No pending clients or missing cipher registry.")
            return
        dt_protocol_start = pd.Timestamp('now')
        self._process_all_rerandomize()
        server_comp_delay = pd.Timestamp('now') - dt_protocol_start
        print("[CS] run time for rerandomize step:", server_comp_delay)

        # Accumulate into time log.
        self.recordTime(dt_protocol_start, "RERANDOMIZE")
        self.current_round = 1
        self.current_iteration += 1
        if (self.current_iteration > self.no_of_iterations):
            return
        self.sendMessage(self.client_num+1, Message({
            "msg": "Continue_Reconstruction",
            "timestamp": currentTime
        }))
        # self.setWakeup(currentTime + server_comp_delay + param.wt_versum_report)

    def receiveMessage(self, currentTime, msg):
        super().receiveMessage(currentTime, msg)
        if msg.body['msg'] == "ENCRYPTED_VECTOR":
            if msg.body['iteration'] == self.current_iteration:
                cipherList = msg.body['ciphertext']
                client_id = msg.body['sender']
                # 暂存客户端数据
                self.pending_clients[client_id] = cipherList

        elif msg.body['msg'] == "REGISTER_RESPONSE_BATCH":
            responses = msg.body['responses']
            for item in responses:
                client_id = item['client_id']
                cipher_id = item['cipher_id']
                self.cipher_registry[client_id] = cipher_id
            self.rerandom(currentTime)

        elif msg.body['msg'] == "Continue_Report":
            self.setWakeup(currentTime + param.wt_versum_report)


    def _batch_register_ciphers(self):
        cipher_batch = []

        for client_id, cipherList in self.user_vectors.items():
            cipher_batch.append({
                "client_id": client_id,
                "cipher": cipherList
            })

        self.sendMessage(self.reg_service_id, Message({
            "msg": "REGISTER_BATCH",
            "cipher_batch": cipher_batch,
            "sender": self.id
        }))


    def _process_all_rerandomize(self):

        for client_id, cipherList in self.user_vectors.items():

            # 重加密
            rerand_cipherList = cipherList

            proof = None  # 若有证明生成逻辑，请替换这里

            self.private_board[client_id] = cipherList

            cipher_id = client_id
            self._update_public_board(cipher_id, cipherList, rerand_cipherList, proof)

        # 清空暂存
        self.pending_clients = {}
        self.cipher_registry = {}
        self.user_vectors = {}


    def _update_public_board(self, reg_id, original_cipher, rerand_cipher, proof):
        """更新公有公告板记录"""
        # 存储格式：{注册ID: (重随机化密文, 证明, 时间戳)}
        self.public_board[reg_id] = {
            'original_cipher' : original_cipher,
            'rerand_cipher': rerand_cipher,
            'proof': proof,
        }


# ======================== UTIL ========================

    def recordTime(self, startTime, categoryName):
        # Accumulate into time log.
        dt_protocol_end = pd.Timestamp('now')
        self.elapsed_time[categoryName] += dt_protocol_end - startTime