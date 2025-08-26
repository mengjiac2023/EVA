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
import util.FedLearning as FedLearning
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
                 X_train=None,
                 y_train=None,
                 input_length=1024,
                 classes=None,
                 nk=10,
                 c=100,
                 m=16):

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

        # MLP inputs
        self.classes = classes
        self.nk = nk
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
        self.global_param_vector = None

        # pick local training data
        self.prng = np.random.Generator(np.random.SFC64())
        obv_per_iter = self.nk #math.floor(X_train.shape[0]/self.num_clients)

        # self.trainX = [np.empty((obv_per_iter,X_train.shape[1]),dtype=X_train.dtype) for i in range(self.no_of_iterations)]
        # self.trainY = [np.empty((obv_per_iter,),dtype=y_train.dtype) for i in range(self.no_of_iterations)]
        self.trainX = []
        self.trainY = []
        for i in range(1):
            #self.input.append(self.prng.integer(input_range));
            slice = self.prng.choice(range(X_train.shape[0]), size=obv_per_iter, replace = False)
            perm = self.prng.permutation(range(X_train.shape[0]))
            p = 0
            while (len(set(y_train[slice])) < len(self.classes)):
                if p >= X_train.shape[0]:
                    print("Dataset does not have the # classes it claims")
                    exit(0)
                add = [perm[p]]
                merge = np.concatenate((slice, add))
                if (len(set(y_train[merge])) > len(set(y_train[slice]))):
                    u, c = np.unique(y_train[slice], return_counts=True)
                    dup = u[c > 1]
                    rm = np.where(y_train[slice] == dup[0])[0][0]
                    slice = np.concatenate((add, np.delete(slice, rm)))
                p += 1

            if (slice.size != obv_per_iter):
                print("n_k not going to be consistent")
                exit(0)

            # Pull together the current local training set.
            self.trainX.append(X_train[slice].copy())
            self.trainY.append(y_train[slice].copy())


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
        self.sendVectors(currentTime)

    def receiveMessage(self, currentTime, msg):
        super().receiveMessage(currentTime, msg)

        if msg.body['msg'] == "AGGREGATED_RESULT" and self.current_iteration != 0:
            # 版本1
            #self.global_param_vector = msg.body['global_param_vector']
            #版本2
            self.global_coefs = msg.body['coefs']
            self.global_int = msg.body['ints']
            self.global_n_iter = msg.body['n_iter']
            self.global_n_layers =msg.body['n_layers']
            self.global_n_outputs = msg.body['n_outputs']
            self.global_t = msg.body['t']
            self.global_nic = msg.body['nic']
            self.global_loss = msg.body['loss']
            self.global_best_loss = msg.body['best_loss']
            self.global_loss_curve = msg.body['loss_curve']
            # Enter next iteration
            self.current_iteration += 1
            if self.current_iteration > self.no_of_iterations:
                return
            dt_protocol_start = pd.Timestamp('now')
            self.sendVectors(currentTime)
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
    def sendVectors(self, currentTime, collection_server_id=0, encrypted_vector=None):
        dt_protocol_start = pd.Timestamp('now')

        # train local data
        #mlp = MLPClassifier(batch_size=64,max_iter=1)
        # mlp = MLPClassifier(
        #     hidden_layer_sizes=(128, 64),  # 隐藏层结构
        #     activation='relu',  # 隐藏层用ReLU（与类别数无关）
        #     solver='adam',  # 优化器
        #     alpha=0.001,  # 正则化
        #     batch_size=64,
        #     learning_rate_init=0.001,
        #     max_iter=1,  # 每次partial_fit仅1 epoch
        #     random_state=42
        #     # 输出层自动使用Softmax（无需设置）
        # )
        #print("CURRENT ITERATION")
        #print(self.current_iteration)
        if self.current_iteration > 1:
            # 版本1
            # mlp = MLPClassifier(warm_start=True)
            # mlp.partial_fit(self.trainX[self.no_of_iterations],self.trainY[self.no_of_iterations],self.classes)
            # mlp = FedLearning.unflatten_model(mlp, self.global_param_vector)
            # 版本2
            #mlp = MLPClassifier(batch_size=64,warm_start=True,max_iter=1)
            mlp = MLPClassifier(
                hidden_layer_sizes=(200,),  # 隐藏层结构
                activation='relu',  # 隐藏层用ReLU（与类别数无关）
                solver='adam',  # 优化器
                alpha=0.001,  # 正则化
                batch_size=64,
                learning_rate_init=0.001,
                max_iter=1,  # 每次partial_fit仅1 epoch
                random_state=42,
                warm_start=True
            )
            mlp.coefs_ = self.global_coefs.copy()
            mlp.intercepts_ = self.global_int.copy()

            mlp.n_iter_ = self.global_n_iter
            mlp.n_layers_ = self.global_n_layers
            mlp.n_outputs_ = self.global_n_outputs
            mlp.t_ = self.global_t
            mlp._no_improvement_count = self.global_nic
            mlp.loss_ = self.global_loss
            mlp.best_loss_ = self.global_best_loss
            mlp.loss_curve_ = self.global_loss_curve.copy()
            mlp.out_activation_ = "softmax"
        else:
            mlp = MLPClassifier(
                hidden_layer_sizes=(200,),  # 隐藏层结构
                activation='relu',  # 隐藏层用ReLU（与类别数无关）
                solver='adam',  # 优化器
                alpha=0.001,  # 正则化
                batch_size=64,
                learning_rate_init=0.001,
                max_iter=1,  # 每次partial_fit仅1 epoch
                random_state=42
                # 输出层自动使用Softmax（无需设置）
            )
        # num epochs
        for j in range(5):
            X_shuffled, y_shuffled = shuffle(self.trainX[0], self.trainY[0])
            mlp.partial_fit(X_shuffled, y_shuffled, self.classes)
            # mlp.partial_fit(self.trainX[self.no_of_iterations],self.trainY[self.no_of_iterations],self.classes)
        # 版本1
        #vec = FedLearning.flatten_model(mlp)
        # 版本2
        vec = FedLearning.flatten_model_with_state(mlp)
        # 使用解密服务器公钥进行Elgamal加密
        # print(f"Client {self.id} start enc vector, length is {len(vec)} and top10 is {vec[:20]}")
        encrypted_vector = ckks.encrypt_vector(self.public_context,vec)
        del mlp
        # print(f"Client {self.id} send vector")
        # 发送给收集服务器（修改消息类型）
        self.sendMessage(collection_server_id,
                             Message({
                                 "msg": "ENCRYPTED_VECTOR",  # 新消息类型
                                 "ciphertext": encrypted_vector,
                                 "iteration": self.current_iteration,
                                 "sender": self.id
                             }))

    def sendVectors_one(self, currentTime, collection_server_id=0, encrypted_vector=None):
        dt_protocol_start = pd.Timestamp('now')
        vec = np.ones(self.vector_len, dtype=self.vector_dtype)
        encrypted_vector = ckks.encrypt_vector(self.public_context, vec)
        # 发送给收集服务器（修改消息类型）
        if __debug__:
            client_comp_delay = pd.Timestamp('now') - dt_protocol_start
            self.logger.info(f"client {self.id} computation delay for vector: {client_comp_delay}")
            self.logger.info(f"client {self.id} sends vector at {currentTime + client_comp_delay}")
        self.sendMessage(collection_server_id,
                         Message({
                             "msg": "ENCRYPTED_VECTOR",  # 新消息类型
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
       
