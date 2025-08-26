import os
import random
from time import time

from Cryptodome.Hash import SHA256
from ecdsa import SECP256k1, ellipticcurve


from Cryptodome.PublicKey import ECC
import numpy as np
import pandas as pd
import dill
from sklearn.neural_network import MLPClassifier
from agent.Agent import Agent
from message.Message import Message
from util import param
from util.crypto import DLEQProof, ecchash, elgamal, ckks
from util.crypto.secretsharing import HexToHexSecretSharer
import util.FedLearning as FedLearning

class SA_DecryptionServer(Agent):
    # 类常量定义路径
    DEFAULT_SK_PATH = os.path.normpath(
        os.path.join(os.path.dirname(__file__), '../../pki_files/ckks_private.ctx')
    )
    def __init__(self, id, name, type,  collection_server, client_ids,
                 random_state=None,
                 input_length=1024,
                 iterations = 5,
                 num_clients = 10,
                 classes=None,
                 X_test=None,
                 y_test=None,
                 X_help=None,
                 y_help=None,
                 nk=None,
                 n=None,
                 c=100,
                 m=16,
                 start_time=None,
                 decryption_sk_path=DEFAULT_SK_PATH):
        super().__init__(id, name, type, random_state)
        # 加载ElGamal私钥
        self.user_committee = {}
        self.committee_threshold = 0
        self.recv_recon_index = {}
        self.recv_committee_shares_sk = {}
        self.client_ids = client_ids
        self.no_of_iterations = iterations
        self.current_iteration = 1
        self.num_clients = num_clients
        self.decryption_sk_path = decryption_sk_path
        if not os.path.exists(decryption_sk_path):
            raise FileNotFoundError(f"Decryption server secret key not found at: {decryption_sk_path}")
        # self.private_context = ckks.load_context(decryption_sk_path)
        self.private_context = None
        self.collection_server = collection_server
        # 初始化聚合存储
        self.aggregated_vector = None
        self.vector_len = input_length  # 与客户端协商的向量长度
        # 新增唤醒间隔配置（单位：秒）
        self.wakeup_interval = pd.Timedelta('20s')
        self.client_count = 0

        # MLP inputs
        self.classes = classes
        self.X_test = X_test
        self.y_test = y_test
        self.X_help = X_help
        self.y_help = y_help
        self.c = c
        self.m = m
        self.nk = nk
        self.n = n
        self.global_coef = None
        self.global_int = None
        
        # Track the current iteration and round of the protocol.
        self.current_iteration = 1
        self.current_round = 0
        self.endtime = start_time
        # Map the message processing functions
        self.aggProcessingMap = {
            0: self.initFunc,
            # 1: self.reconstruction,
        }

        self.namedict = {
            0: "init",
            # 1: "reconstruction",
        }

        # agent accumulation of elapsed times by category of tasks
        self.elapsed_time = {'RESK': pd.Timedelta(0),
            'RECONSTRUCTION': pd.Timedelta(0),}

    def kernelStarting(self, startTime):
        # self.kernel is set in Agent.kernelInitializing()

        # Initialize custom state properties into which we will accumulate results later.
        self.kernel.custom_state['ds_reconstruction'] = pd.Timedelta(0)
        self.kernel.custom_state['ds_resk'] = pd.Timedelta(0)
        # This agent should have negligible (or no) computation delay until otherwise specified.
        self.setComputationDelay(0)

        # Request a wake-up call as in the base Agent.
        super().kernelStarting(startTime)

    def kernelStopping(self):
        # Add the server time components to the custom state in the Kernel, for output to the config.
        # Note that times which should be reported in the mean per iteration are already so computed.
        self.kernel.custom_state['ds_reconstruction'] += (
            self.elapsed_time['RECONSTRUCTION'] / self.no_of_iterations)
        self.kernel.custom_state['ds_resk'] += (
            self.elapsed_time['RESK'] / self.no_of_iterations)
        # Allow the base class to perform stopping activities.
        super().kernelStopping()
        
    # def wakeup(self, currentTime):
    #     """定时唤醒处理逻辑"""
    #     # 调用公告板检查
    #     public_board = self._fetch_public_board()  # 需要实现公告板获取逻辑
    #     # 新增空值检查
    #     if not public_board:
    #         print(f"空公告板 @ {currentTime}，跳过本轮聚合")
    #         self.setWakeup(currentTime + self.wakeup_interval)
    #         return
    #
    #     self.checkPublicBoard(public_board)
    #
    #     # 广播聚合结果给所有客户端
    #     aggregated_result = self.get_aggregated_result()
    #     print(f"Server {self.id} agg, length is {len(aggregated_result)} and top10 is {aggregated_result[:20]}")
    #     if aggregated_result is not None:
    #         self._broadcast_result(currentTime, aggregated_result)
    #
    #     self.current_iteration += 1
    #     if self.current_iteration <= self.no_of_iterations:
    #         # 设置下次唤醒
    #         self.setWakeup(currentTime + self.wakeup_interval)

    def wakeup(self, currentTime):
        super().wakeup(currentTime)
        print(f"[DS] wakeup in iteration {self.current_iteration} at function {self.namedict[self.current_round]}; current time is {currentTime}")

        # In the k-th iteration
        self.aggProcessingMap[self.current_round](currentTime)

    def receiveMessage(self, currentTime, msg):
        super().receiveMessage(currentTime, msg)
        if msg.body['msg'] == "Continue_Reconstruction":
            # self.reconstruction(currentTime)
            for id in self.user_committee:
                self.sendMessage(id,
                                 Message({"msg": "DEC",
                                          "iteration": self.current_iteration,
                                          "sender": self.id
                                          }),
                                 tag="comm_sign_server")
        elif msg.body['msg'] == "SHARED_RESULT":
            sender_id = msg.body['sender']
            if msg.body['iteration'] == self.current_iteration:
                self.recv_committee_shares_sk[sender_id] = msg.body['shared_sk']
                self.recv_recon_index[sender_id] = msg.body['committee_member_idx']
                valid_shares = {k: v for k, v in self.recv_committee_shares_sk.items() if v is not None}
                if len(valid_shares) > self.committee_threshold:
                    dt_protocol_start = pd.Timestamp('now')

                    all_shares = list(valid_shares.values())
                    selected = random.sample(all_shares, self.committee_threshold)
                    recovered_hex = HexToHexSecretSharer.recover_secret(selected)
                    recovered_path = bytes.fromhex(recovered_hex).decode()
                    # Optional: 输出验证
                    print("✅ 恢复的路径:", recovered_path)
                    self.private_context = ckks.load_context(recovered_path)

                    server_comp_delay = pd.Timestamp('now') - dt_protocol_start

                    print("[DS] run time for resk step:", server_comp_delay)

                    # Accumulate into time log.
                    self.recordTime(dt_protocol_start, "RESK")

                    self.reconstruction(currentTime)
                    self.recv_committee_shares_sk = {}
                    self.recv_recon_index = {}



    def initFunc(self, currentTime):
        dt_protocol_start = pd.Timestamp('now')

        # Setup committee (decryptors).
        self.user_committee = param.choose_committee(param.root_seed,
                                                     param.committee_size,
                                                     self.num_clients)
        self.committee_threshold = int(param.fraction * len(self.user_committee))
        # Simulate the Shamir share of SK at each decryptor
        hex_secret = self.decryption_sk_path.encode().hex()
        sk_shares = HexToHexSecretSharer.split_secret(hex_secret, self.committee_threshold, len(self.user_committee))

        cnt = 0
        for id in self.user_committee:
            self.sendMessage(id,
                             Message({"msg": "COMMITTEE_SHARED_SK",
                                      "committee_member_idx": cnt + 1,  # the share evaluation x-point starts at 1
                                      "sk_share": sk_shares[cnt],
                                      }),
                             tag="comm_dec_server")
            cnt += 1

        self.current_round = 1

    def reconstruction(self, currentTime):
        print(f"[DS] wakeup in iteration {self.current_iteration} at function reconstruction; current time is {currentTime}")
        dt_protocol_start = pd.Timestamp('now')

        # 调用公告板检查
        public_board = self._fetch_public_board()  # 需要实现公告板获取逻辑
        self.checkPublicBoard_V2(public_board)

        # 广播聚合结果给所有客户端
        aggregated_result = self.get_aggregated_result()
        self._broadcast_result(currentTime, aggregated_result)

        server_comp_delay = pd.Timestamp('now') - dt_protocol_start

        print("[DS] run time for reconstruction step:", server_comp_delay)

        # Accumulate into time log.
        self.recordTime(dt_protocol_start, "RECONSTRUCTION")
        end_time = time()
        print(f"{self.current_iteration} END TIME:", end_time, "One Epoch cost", end_time - self.endtime)
        self.endtime = end_time
        self.current_iteration += 1
        if self.current_iteration > self.no_of_iterations:
            return
        self.sendMessage(0, Message({
            "msg": "Continue_Report",
            "timestamp": currentTime
        }))
        # self.setWakeup(currentTime + server_comp_delay + param.wt_versum_reconstruction)

    def _fetch_public_board(self):
        """直接访问并清空收集服务器的公告板"""
        public_board = self.collection_server.public_board.copy()

        # 清空收集服务器的公告板
        self.collection_server.public_board = {}

        return public_board

    def _broadcast_result_one(self, currentTime, result):
        final_sum = result
        print("[DS] final sum:", final_sum)
        self.aggregated_vector = None
        """向所有客户端广播结果"""
        # 实际需要实现客户端列表获取逻辑，这里假设有client_ids属性
        for client_id in self.client_ids:
            self.sendMessage(client_id, Message({
                "msg": "AGGREGATED_RESULT",
                "timestamp": currentTime
            }))

    def _broadcast_result(self, currentTime, result):

        rec = self.client_count
        final_sum = result
        # MLP
        avg_vec = final_sum / rec
        print(len(avg_vec))
        self.aggregated_vector = None
        """向所有客户端广播结果"""
        # 实际需要实现客户端列表获取逻辑，这里假设有client_ids属性
        for client_id in self.client_ids:
            self.sendMessage(client_id, Message({
                "msg": "AGGREGATED_RESULT",
                "global_param_vector": avg_vec,
                "timestamp": currentTime
            }))

    def verify_rerandomization(self, original_cipher, rerand_cipher, proof,r_prime):
        """验证重随机化的零知识证明"""
        # 计算密文差异
        delta_c0 = rerand_cipher[0] - original_cipher[0]
        delta_c1 = rerand_cipher[1] - original_cipher[1]
        r=r_prime

        # 验证DLEQ证明
        return DLEQProof.verify(
            proof=proof,
            g=ECC.EccPoint(ecchash.Gx, ecchash.Gy),  # 椭圆曲线基点
            h=self.get_public_key(),  # 解密服务器公钥
            c0_diff=delta_c0,
            c1_diff=delta_c1
        )
    # c0_diff, c1_diff
    def decrypt_vector(self, cipherList):
        return ckks.decrypt_vector(self.private_context, cipherList)

    def add_vector(self, cipherList):
        return ckks.decrypt_vector(self.private_context, cipherList)

    def checkPublicBoard(self, public_board):
        """处理公告板公有部分的记录"""
        client_count = 0  # 新增客户端计数器
        for record_id, record in public_board.items():
            rerand_cipher = record['rerand_cipher']

            # 验证证明有效性
            # if self.verify_rerandomization(original_cipher, rerand_cipher, proof,r_prime):
            if 1:
                decrypted = self.decrypt_vector(rerand_cipher)
                if self.aggregated_vector is None:
                    self.aggregated_vector = decrypted
                else:
                    self.aggregated_vector = [a + b for a, b in zip(self.aggregated_vector, decrypted)]
                client_count += 1
        self.aggregated_vector = np.round(np.array(self.aggregated_vector))
        # 全局平均（新增）
        if client_count > 0:
            self.client_count = client_count

    def checkPublicBoard_V2(self, public_board):
        """处理公告板公有部分的记录"""
        client_count = 0  # 新增客户端计数器
        for record_id, record in public_board.items():
            rerand_cipher = record['rerand_cipher']

            # 验证证明有效性
            # if self.verify_rerandomization(original_cipher, rerand_cipher, proof,r_prime):
            if 1:
                if self.aggregated_vector is None:
                    self.aggregated_vector = rerand_cipher
                else:
                    self.aggregated_vector = ckks.add_encrypted_vectors(self.aggregated_vector, rerand_cipher)
                client_count += 1
        self.aggregated_vector = self.decrypt_vector(self.aggregated_vector)
        self.aggregated_vector = np.array(self.aggregated_vector)
        # 全局平均（新增）
        if client_count > 0:
            self.client_count = client_count

    def get_public_key(self):
        """生成对应的公钥点"""
        return ECC.EccPoint(ecchash.Gx, ecchash.Gy) * self.decryption_sk.d

    def get_aggregated_result(self):
        """获取当前聚合结果"""
        return self.aggregated_vector.copy() if self.aggregated_vector is not None else None

    # ======================== UTIL ========================

    def recordTime(self, startTime, categoryName):
        dt_protocol_end = pd.Timestamp('now')
        self.elapsed_time[categoryName] += dt_protocol_end - startTime


    def agent_print(*args, **kwargs):
        """
        Custom print function that adds a [Server] header before printing.

        Args:
            *args: Any positional arguments that the built-in print function accepts.
            **kwargs: Any keyword arguments that the built-in print function accepts.
        """
        print(*args, **kwargs)

# 椭圆曲线参数（需与客户端保持一致）
ecchash.Gx = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
ecchash.Gy = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5