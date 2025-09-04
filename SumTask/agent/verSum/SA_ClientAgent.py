import pickle

from agent.Agent import Agent
from agent.flamingo.SA_ServiceAgent import SA_ServiceAgent as ServiceAgent
from message.Message import Message

import dill
import time
import logging

import math
import libnum
import numpy as np
import pandas as pd
import random

# pycryptodomex library functions
from Cryptodome.PublicKey import ECC
from Cryptodome.Cipher import AES, ChaCha20
from Cryptodome.Random import get_random_bytes
from Cryptodome.Hash import SHA256
from Cryptodome.Signature import DSS

# other user-level crypto functions
import hashlib
from util import param
from util.crypto import ecchash
from util.crypto import ckks

from sklearn.neural_network import MLPClassifier


# The PPFL_TemplateClientAgent class inherits from the base Agent class.
class SA_ClientAgent(Agent):

    # Default param:
    # num of iterations = 4
    # key length = 32 bytes
    # neighbors ~ 2 * log(num per iter) 
    def __init__(self, id, name, type,
                 iterations=4,
                 key_length=32,
                 num_clients=128,
                 neighborhood_size=1,
                 debug_mode=0,
                 random_state=None,
                 X_train=None,
                 y_train=None,
                 input_length=1024,
                 classes=None,
                 nk=10,
                 c=100,
                 m=16):

        # Base class init
        super().__init__(id, name, type, random_state)

        self.committee_member_idx = None
        self.committee_shared_sk = None
        self.public_context = ckks.load_context('pki_files/ckks_public.ctx')

        # Iteration counter
        self.no_of_iterations = iterations
        self.current_iteration = 1
        self.current_base = 0

        # MLP inputs
        self.classes = classes
        self.nk = nk
        if self.classes:
            if (self.nk < len(self.classes)) or (self.nk >= X_train.shape[0]):
                print("nk is a bad size")
                exit(0)

        self.global_coefs = None
        self.global_int = None
        self.global_n_iter = None
        self.global_n_layers = None
        self.global_n_outputs = None
        self.global_t = None
        self.global_nic = None
        self.global_loss = None
        self.global_best_loss = None
        self.global_loss_curve = None
        self.c = c
        self.m = m

        # pick local training data
        self.prng = np.random.Generator(np.random.SFC64())
        obv_per_iter = self.nk  # math.floor(X_train.shape[0]/self.num_clients)
        # Set logger
        self.logger = logging.getLogger("Log")
        self.logger.setLevel(logging.INFO)
        if debug_mode:
            logging.basicConfig()

        """ Set parameters. """
        self.num_clients = num_clients
        self.neighborhood_size = neighborhood_size
        self.vector_len = param.vector_len
        self.vector_dtype = param.vector_type
        self.prime = ecchash.n
        self.key_length = key_length
        self.neighbors_list = set()  # neighbors
        self.cipher_stored = None  # Store cipher from server across steps

        # If it is in the committee:
        # read pubkeys of every other client and precompute pairwise keys
        self.symmetric_keys = {}

        # Accumulate this client's run time information by step.
        self.elapsed_time = {'REPORT': pd.Timedelta(0),
                             'CROSSCHECK': pd.Timedelta(0),
                             'RECONSTRUCTION': pd.Timedelta(0),
                             }
        self.elapsed_cost = {'REPORT': 0,
                             'CROSSCHECK': 0,
                             'RECONSTRUCTION': 0,
                             }

        # State flag
        self.setup_complete = False

    # Simulation lifecycle messages.
    def kernelStarting(self, startTime):

        # Initialize custom state properties into which we will later accumulate results.
        # To avoid redundancy, we allow only the first client to handle initialization.
        if self.id == 1:
            self.kernel.custom_state['clt_report'] = pd.Timedelta(0)
            self.kernel.custom_state['clt_crosscheck'] = pd.Timedelta(0)
            self.kernel.custom_state['clt_reconstruction'] = pd.Timedelta(0)
            self.kernel.custom_state['clt_report_cost'] = 0
            self.kernel.custom_state['clt_crosscheck_cost'] = 0
            self.kernel.custom_state['clt_reconstruction_cost'] = 0

        # Find the PPFL service agent, so messages can be directed there.
        self.serviceAgentID = self.kernel.findAgentByType(ServiceAgent)

        self.setComputationDelay(0)

        # Request a wake-up call as in the base Agent.  Noise is kept small because
        # the overall protocol duration is so short right now.  (up to one microsecond)
        super().kernelStarting(startTime +
                               pd.Timedelta(self.random_state.randint(low=0, high=1000), unit='ns'))

    def kernelStopping(self):

        # Accumulate into the Kernel's "custom state" this client's elapsed times per category.
        # Note that times which should be reported in the mean per iteration are already so computed.
        # These will be output to the config (experiment) file at the end of the simulation.

        self.kernel.custom_state['clt_report'] += (
                self.elapsed_time['REPORT'] / self.no_of_iterations)
        self.kernel.custom_state['clt_crosscheck'] += (
                self.elapsed_time['CROSSCHECK'] / self.no_of_iterations)
        self.kernel.custom_state['clt_reconstruction'] += (
                self.elapsed_time['RECONSTRUCTION'] / self.no_of_iterations)
        self.kernel.custom_state['clt_report_cost'] += (
                self.elapsed_cost['REPORT'] / self.no_of_iterations)
        self.kernel.custom_state['clt_crosscheck_cost'] += (
                self.elapsed_cost['CROSSCHECK'] / self.no_of_iterations)
        self.kernel.custom_state['clt_reconstruction_cost'] += (
                self.elapsed_cost['RECONSTRUCTION'] / self.no_of_iterations)
        super().kernelStopping()

    # Simulation participation messages.
    def wakeup(self, currentTime):
        super().wakeup(currentTime)
        dt_wake_start = pd.Timestamp('now')
        self.sendVectors_one(currentTime)

    def receiveMessage(self, currentTime, msg):
        super().receiveMessage(currentTime, msg)

        if msg.body['msg'] == "AGGREGATED_RESULT" and self.current_iteration != 0:
            self.current_iteration += 1
            if self.current_iteration <= self.no_of_iterations:
                dt_protocol_start = pd.Timestamp('now')
                self.sendVectors_one(currentTime)
                self.recordTime(dt_protocol_start, "REPORT")
        elif msg.body['msg'] == "CIPHER_REGISTERED" and self.current_iteration != 0:
            pass
        elif msg.body['msg'] == "COMMITTEE_SHARED_SK":
            self.committee_shared_sk = msg.body['sk_share']
            self.committee_member_idx = msg.body['committee_member_idx']
        elif msg.body['msg'] == "DEC":
            if msg.body['iteration'] == self.current_iteration:
                dt_protocol_start = pd.Timestamp('now')
                self.sendMessage(msg.body['sender'],
                                 Message({"msg": "SHARED_RESULT",
                                          "iteration": self.current_iteration,
                                          "sender": self.id,
                                          "shared_sk": self.committee_shared_sk,
                                          "committee_member_idx": self.committee_member_idx,
                                          }),
                                 tag="comm_secret_sharing")
                # self.recordCost(cost=compute_message_body_size({"msg": "SHARED_RESULT",
                #                           "iteration": self.current_iteration,
                #                           "sender": self.id,
                #                           "shared_sk": self.committee_shared_sk,
                #                           "committee_member_idx": self.committee_member_idx,
                #                           })
                #                 , categoryName="RECONSTRUCTION")

                self.recordTime(dt_protocol_start, 'RECONSTRUCTION')

    ###################################
    # Round logics
    ###################################
    def sendVectors_one(self, currentTime, collection_server_id=0, encrypted_vector=None):
        dt_protocol_start = pd.Timestamp('now')
        vec = np.ones(self.vector_len, dtype=self.vector_dtype)
        encrypted_vector = ckks.encrypt_vector(self.public_context, vec)
        if __debug__:
            client_comp_delay = pd.Timestamp('now') - dt_protocol_start
            self.logger.info(f"client {self.id} computation delay for vector: {client_comp_delay}")
            self.logger.info(f"client {self.id} sends vector at {currentTime + client_comp_delay}")
        self.sendMessage(collection_server_id,
                         Message({
                             "msg": "ENCRYPTED_VECTOR",
                             "ciphertext": encrypted_vector,
                             "iteration": self.current_iteration,
                             "sender": self.id
                         }))
        # self.recordCost(cost=compute_message_body_size({
        #                      "msg": "ENCRYPTED_VECTOR",
        #                      "iteration": self.current_iteration,
        #                      "sender": self.id
        #                  })+ckksvector_list_size_bytes(encrypted_vector),categoryName="REPORT")

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


def ckksvector_list_size_bytes(ckksvector_list):
    total_bytes = 0
    for vec in ckksvector_list:
        serialized = vec.serialize()  # bytes
        total_bytes += len(serialized)
    return total_bytes