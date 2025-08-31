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

# other user-level crypto functions
import hashlib
from util import param
from util.crypto import ecchash
from util.crypto import ckks
from sklearn.neural_network import MLPClassifier
from sklearn.utils import shuffle


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
                 input_length=1024,
                 ):

        # Base class init
        super().__init__(id, name, type, random_state)

        # 加载解密服务器公钥
        self.committee_member_idx = None
        self.committee_shared_sk = None
        self.public_context = ckks.load_context('pki_files/ckks_public.ctx')

        # Iteration counter
        self.no_of_iterations = iterations
        self.current_iteration = 1
        self.current_base = 0
        self.global_param_vector = None

        # pick local training data
        self.prng = np.random.Generator(np.random.SFC64())
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
        self.neighbors_list = set() # neighbors
        self.cipher_stored = None   # Store cipher from server across steps

        # If it is in the committee:
        # read pubkeys of every other client and precompute pairwise keys
        self.symmetric_keys = {}

        # Accumulate this client's run time information by step.
        self.elapsed_time = {'REPORT': pd.Timedelta(0),
                             'CROSSCHECK': pd.Timedelta(0),
                             'RECONSTRUCTION': pd.Timedelta(0),
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

        super().kernelStopping()

    # Simulation participation messages.
    def wakeup(self, currentTime):
        super().wakeup(currentTime)
        dt_wake_start = pd.Timestamp('now')
        self.sendVectors_one(currentTime)

    def receiveMessage(self, currentTime, msg):
        super().receiveMessage(currentTime, msg)

        if msg.body['msg'] == "AGGREGATED_RESULT" and self.current_iteration != 0:
            # Enter next iteration
            self.current_iteration += 1
            if self.current_iteration > self.no_of_iterations:
                return
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
       
