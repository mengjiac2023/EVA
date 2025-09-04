import os
import pickle
import random
import time

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


class SA_DecryptionServer(Agent):
    DEFAULT_SK_PATH = os.path.normpath(
        os.path.join(os.path.dirname(__file__), '../../pki_files/ckks_private.ctx')
    )

    def __init__(self, id, name, type, collection_server, client_ids,
                 random_state=None,
                 input_length=1024,
                 iterations=5,
                 num_clients=10,
                 classes=None,
                 X_test=None,
                 y_test=None,
                 X_help=None,
                 y_help=None,
                 nk=None,
                 n=None,
                 c=100,
                 m=16,
                 decryption_sk_path=DEFAULT_SK_PATH,
                 start_time=None):
        super().__init__(id, name, type, random_state)
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
        self.aggregated_vector = None
        self.vector_len = input_length
        self.wakeup_interval = pd.Timedelta('20s')
        self.client_count = 0
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
        self.endtime = start_time
        # Track the current iteration and round of the protocol.
        self.current_iteration = 1
        self.current_round = 0

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
                             'RECONSTRUCTION': pd.Timedelta(0), }
        self.elapsed_cost = {'RESK': 0,
                             'RECONSTRUCTION': 0, }

    def kernelStarting(self, startTime):
        # self.kernel is set in Agent.kernelInitializing()

        # Initialize custom state properties into which we will accumulate results later.
        self.kernel.custom_state['ds_reconstruction'] = pd.Timedelta(0)
        self.kernel.custom_state['ds_resk'] = pd.Timedelta(0)
        self.kernel.custom_state['ds_reconstruction_cost'] = 0
        self.kernel.custom_state['ds_resk_cost'] = 0
        # This agent should have negligible (or no) computation delay until otherwise specified.
        self.setComputationDelay(0)

        # Request a wake-up call as in the base Agent.
        super().kernelStarting(startTime)

    def kernelStopping(self):
        # Add the server time components to the custom state in the Kernel, for output to the config.
        # Note that times which should be reported in the mean per iteration are already so computed.
        self.kernel.custom_state['ds_reconstruction'] += (
                self.elapsed_time['RECONSTRUCTION'] / (self.no_of_iterations - 1))
        self.kernel.custom_state['ds_resk'] += (
                self.elapsed_time['RESK'] / (self.no_of_iterations - 1))
        self.kernel.custom_state['ds_reconstruction_cost'] += (
                self.elapsed_cost['RECONSTRUCTION'] / (self.no_of_iterations - 1))
        self.kernel.custom_state['ds_resk_cost'] += (
                self.elapsed_cost['RESK'] / (self.no_of_iterations - 1))
        # Allow the base class to perform stopping activities.
        super().kernelStopping()


    def wakeup(self, currentTime):
        super().wakeup(currentTime)
        print(
            f"[DS] wakeup in iteration {self.current_iteration} at function {self.namedict[self.current_round]}; current time is {currentTime}")

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
                if len(self.recv_committee_shares_sk) > self.committee_threshold:
                    dt_protocol_start = pd.Timestamp('now')

                    all_shares = list(self.recv_committee_shares_sk.values())
                    selected = random.sample(all_shares, self.committee_threshold)
                    recovered_hex = HexToHexSecretSharer.recover_secret(selected)
                    recovered_path = bytes.fromhex(recovered_hex).decode()
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
        print(
            f"[DS] wakeup in iteration {self.current_iteration} at function reconstruction; current time is {currentTime}")
        dt_protocol_start = pd.Timestamp('now')

        public_board = self._fetch_public_board()
        self.checkPublicBoard_V2(public_board)

        aggregated_result = self.get_aggregated_result()
        self._broadcast_result_one(currentTime, aggregated_result)

        server_comp_delay = pd.Timestamp('now') - dt_protocol_start

        print("[DS] run time for reconstruction step:", server_comp_delay)

        # Accumulate into time log.
        self.recordTime(dt_protocol_start, "RECONSTRUCTION")
        end_time = time.time()
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
        public_board = self.collection_server.public_board.copy()

        self.collection_server.public_board = {}

        return public_board

    def _broadcast_result_one(self, currentTime, result):
        final_sum = result
        print("[DS] final sum:", len(final_sum))
        self.aggregated_vector = None
        self.vector_len = 16000
        output = [1] * self.vector_len
        for client_id in self.client_ids:
            self.sendMessage(client_id, Message({
                "msg": "AGGREGATED_RESULT",
                "timestamp": currentTime
            }))

    def _broadcast_result(self, currentTime, result):

        rec = self.client_count
        final_sum = result
        # MLP
        mlp = MLPClassifier(max_iter=1, warm_start=True)
        mlp.partial_fit(self.X_help, self.y_help, self.classes)

        mlp.n_iter_ = int(final_sum[0] / rec)
        mlp.n_layers_ = int(final_sum[1] / rec)
        mlp.n_outputs_ = int(final_sum[2] / rec)
        mlp.t_ = int(final_sum[3] / rec)

        nums = np.vectorize(lambda d: d * 1 / rec)(final_sum)
        nums = np.vectorize(lambda d: (d / pow(2, self.m)) \
                                      - self.c)(nums)

        # use aggregation to set MLP classifier
        c_indx = []
        i_indx = []

        x = 7
        for z in range(mlp.n_layers_ - 1):
            a = int(final_sum[x] / rec)
            x += 1
            b = int(final_sum[x] / rec)
            x += 1
            c_indx.append((a, b))
        for z in range(mlp.n_layers_ - 1):
            a = int(final_sum[x] / rec)
            i_indx.append(a)
            x += 1

        # x += mlp.n_iter_
        i_nums = []
        c_nums = []
        for z in range(mlp.n_layers_ - 1):
            a, b = c_indx[z]
            c_nums.append(np.reshape(np.array(nums[x:(x + (a * b))]), (a, b)))
            x += (a * b)
        for z in range(mlp.n_layers_ - 1):
            a = i_indx[z]
            i_nums.append(np.reshape(np.array(nums[x:(x + a)]), (a,)))

        mlp.coefs_ = c_nums
        mlp.intercepts_ = i_nums

        print("[Server] MLP SCORE: ", mlp.score(self.X_test, self.y_test))
        self.aggregated_vector = None
        for client_id in self.client_ids:
            self.sendMessage(client_id, Message({
                "msg": "AGGREGATED_RESULT",
                "coefs": mlp.coefs_,
                "ints": mlp.intercepts_,
                "n_iter": mlp.n_iter_,
                "n_layers": mlp.n_layers_,
                "n_outputs": mlp.n_outputs_,
                "t": mlp.t_,
                "nic": mlp._no_improvement_count,
                "loss": mlp.loss_,
                "best_loss": mlp.best_loss_,
                "loss_curve": mlp.loss_curve_,
                "timestamp": currentTime
            }))

    def verify_rerandomization(self, original_cipher, rerand_cipher, proof, r_prime):
        delta_c0 = rerand_cipher[0] - original_cipher[0]
        delta_c1 = rerand_cipher[1] - original_cipher[1]
        r = r_prime

        return DLEQProof.verify(
            proof=proof,
            g=ECC.EccPoint(ecchash.Gx, ecchash.Gy),
            h=self.get_public_key(),
            c0_diff=delta_c0,
            c1_diff=delta_c1
        )

    # c0_diff, c1_diff
    def decrypt_vector(self, cipherList):
        return ckks.decrypt_vector(self.private_context, cipherList)

    def add_vector(self, cipherList):
        return ckks.decrypt_vector(self.private_context, cipherList)

    def checkPublicBoard(self, public_board):
        client_count = 0
        for record_id, record in public_board.items():
            rerand_cipher = record['rerand_cipher']

            if 1:
                decrypted = self.decrypt_vector(rerand_cipher)
                if self.aggregated_vector is None:
                    self.aggregated_vector = decrypted
                else:
                    self.aggregated_vector = [a + b for a, b in zip(self.aggregated_vector, decrypted)]
                client_count += 1
        self.aggregated_vector = np.round(np.array(self.aggregated_vector))
        if client_count > 0:
            self.client_count = client_count

    def checkPublicBoard_V2(self, public_board):
        client_count = 0
        for record_id, record in public_board.items():
            rerand_cipher = record['rerand_cipher']

            if 1:
                if self.aggregated_vector is None:
                    self.aggregated_vector = rerand_cipher
                else:
                    self.aggregated_vector = ckks.add_encrypted_vectors(self.aggregated_vector, rerand_cipher)
                client_count += 1
        self.aggregated_vector = self.decrypt_vector(self.aggregated_vector)
        self.aggregated_vector = np.round(np.array(self.aggregated_vector))
        if client_count > 0:
            self.client_count = client_count

    def get_public_key(self):
        return ECC.EccPoint(ecchash.Gx, ecchash.Gy) * self.decryption_sk.d

    def get_aggregated_result(self):
        return self.aggregated_vector.copy() if self.aggregated_vector is not None else None

    # ======================== UTIL ========================

    def recordTime(self, startTime, categoryName):
        dt_protocol_end = pd.Timestamp('now')
        self.elapsed_time[categoryName] += dt_protocol_end - startTime

    def recordCost(self, cost, categoryName):
        self.elapsed_cost[categoryName] += cost

    def agent_print(*args, **kwargs):
        """
        Custom print function that adds a [Server] header before printing.

        Args:
            *args: Any positional arguments that the built-in print function accepts.
            **kwargs: Any keyword arguments that the built-in print function accepts.
        """
        print(*args, **kwargs)


def compute_message_body_size(body_dict, unit="B", verbose=False):
    try:
        data = pickle.dumps(body_dict)
        size_bytes = len(data)

        if unit.upper() == "B":
            size = size_bytes
        elif unit.upper() == "MB":
            size = size_bytes / (1024 * 1024)
        else:
            size = size_bytes / 1024

        if verbose:
            print(f"[INFO] Message body size: {size:.2f} {unit.upper()}")

        return size

    except (TypeError, ValueError) as e:
        print("[ERROR] Message body contains non-serializable data:", e)
        return -1

ecchash.Gx = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
ecchash.Gy = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5