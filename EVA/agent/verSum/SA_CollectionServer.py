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
    DEFAULT_PK_PATH = os.path.normpath(
        os.path.join(os.path.dirname(__file__), '../../pki_files/ckks_public.ctx')
    )
    def __init__(self, reg_service_id, id, name, type,
                 random_state,
                 client_num,
                 iterations,
                 decryption_pk_path=DEFAULT_PK_PATH):
        super().__init__(id, name, type, random_state)

        self.reg_service_id = reg_service_id
        self.public_board = {}
        self.private_board = {}
        self.client_num = client_num
        self.rerand_cipher = {}
        self.public_context = ckks.load_context(decryption_pk_path)

        self.cipher_registry = {}  # {client_id: cipher_id}
        self.pending_clients = {}  # {client_id: cipherList}
        self.user_vectors = {}
        self.no_of_iterations = iterations
        # Track the current iteration and round of the protocol.
        self.current_iteration = 1
        self.current_round = 0

        # Map the message processing functions
        self.aggProcessingMap = {
            0: self.initFunc,
            1: self.report,
            # 2: self.rerandom,
        }

        self.namedict = {
            0: "init",
            1: "report",
            # 2: "random",
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

    # Simulation participation messages.

    # The service agent wakeup at the end of each round
    # More specifically, it stores the messages on receiving the msgs;
    # When the timing out happens, or it collects enough number of msgs,
    # (i.e., from all clients it is waiting for),
    # it starts processing and replying the messages.

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
        self._batch_register_ciphers()
        server_comp_delay = pd.Timestamp('now') - dt_protocol_start
        print("[CS] run time for report step:", server_comp_delay)
        # Accumulate into time log.
        self.recordTime(dt_protocol_start, "REPORT")
        self.current_round = 1
        # self.setWakeup(currentTime + server_comp_delay + param.wt_versum_rerandomize)

    def rerandom(self,currentTime):
        if not self.user_vectors or not self.cipher_registry:
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
                "cipher": cipherList[:1]
            })

        self.sendMessage(self.reg_service_id, Message({
            "msg": "REGISTER_BATCH",
            "cipher_batch": cipher_batch,
            "sender": self.id
        }))

    def _register_cipher(self, client_id, cipherList):
        self.sendMessage(self.reg_service_id,
                         Message({
                             "msg": "REGISTER",
                             "cipher": cipherList,
                             "client_id": client_id,
                             "sender" : self.id
                         }))

    def rerandomize(self, cipherList, sender):
        original_ids = np.arange(1, self.client_num + 1)
        permuted_ids = np.random.permutation(original_ids)
        r_prime = int.from_bytes(get_random_bytes(32), 'big') % ecchash.n
        id_C = permuted_ids[sender - 1]
        rerand_cipherList = ckks.rerandomize_ckks_vector(self.public_context,cipherList)
        proofs = None
        self.rerand_cipher[id_C] = rerand_cipherList

        return rerand_cipherList, proofs, r_prime

    def _process_all_rerandomize(self):
        original_ids = np.arange(1, self.client_num + 1)
        permuted_ids = np.random.permutation(original_ids)
        print("now accept cipher_register",len(self.cipher_registry),"and",len(self.user_vectors))
        self.permuted_id_map = {orig: perm for orig, perm in zip(original_ids, permuted_ids)}
        first_cipher = list(self.user_vectors.values())[0]
        noise_vector = ckks.noise_ckks_vector(self.public_context,first_cipher)
        for client_id, cipherList in self.user_vectors.items():
            new_id = self.permuted_id_map[client_id]

            rerand_cipherList = ckks.add_encrypted_vectors(cipherList, noise_vector)

            proof = None

            self.rerand_cipher[new_id] = rerand_cipherList
            self.private_board[client_id] = cipherList

            cipher_id = self.cipher_registry[client_id]
            self._update_public_board(cipher_id, cipherList, rerand_cipherList, proof)

            self.sendMessage(client_id, Message({
                "msg": "CIPHER_REGISTERED",
                "cipher_id": cipher_id
            }))

        self.pending_clients = {}
        self.cipher_registry = {}
        self.user_vectors = {}


    def _update_public_board(self, reg_id, original_cipher, rerand_cipher, proof):
        self.public_board[reg_id] = {
            'original_cipher' : original_cipher,
            'rerand_cipher': rerand_cipher,
            'proof': proof,
        }

    def generate_challenge(self, original_cipher, new_c0, new_c1):
        hash_input = f"{original_cipher[0].x}{original_cipher[0].y}{original_cipher[1].x}{original_cipher[1].y}{new_c0.x}{new_c0.y}{new_c1.x}{new_c1.y}".encode()
        return int.from_bytes(SHA256.new(hash_input).digest(), 'big') % ecchash.n

    def generate_nizk_proof(self, original_cipher, new_c0, new_c1, r_prime):
        challenge = self.generate_challenge(original_cipher, new_c0, new_c1)
        response = r_prime + challenge * int.from_bytes(SHA256.new(f"{original_cipher}".encode()).digest(),
                                                        'big') % ecchash.n

        return {
            'challenge': challenge,
            'response': response,
            'original_cipher': original_cipher,
            'new_c0': new_c0,
            'new_c1': new_c1
        }

# ======================== UTIL ========================

    def recordTime(self, startTime, categoryName):
        # Accumulate into time log.
        dt_protocol_end = pd.Timestamp('now')
        self.elapsed_time[categoryName] += dt_protocol_end - startTime