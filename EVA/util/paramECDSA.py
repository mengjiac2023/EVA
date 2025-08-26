from Cryptodome.Cipher import AES, ChaCha20
from Cryptodome.Random import get_random_bytes
import numpy as np
import pandas as pd
import math
import random
from ecdsa import SECP256k1, ellipticcurve

# System parameters
vector_len = 16000
vector_type = 'uint32'
# committee_size = 60
committee_size = 30
fraction = 1/3

# 设置随机种子，确保每次运行得到相同的随机矩阵
seed_value = 42
np.random.seed(seed_value)
# 生成不满秩矩阵 U
rows, cols = 10, 79510  # 让列数小于行数，确保秩不足
U = np.random.randn(rows, cols)   # 随机初始化 U
U[:, 0] = U[:, 1]  # 让第一列和第二列相同，制造线性相关

# 公共参数
q = 3329

# 使用 SECP256k1 曲线
curve = SECP256k1
G = curve.generator  # 基点
n = curve.order       # 群阶
# 设置种子，确保随机数是可重复的
random.seed(42)  # 设置一个固定的种子
r = random.randint(0, n-1)  # 用随机数生成器生成 [0, n-1] 之间的随机数
# 定点编码：对浮点数进行放大
scale = 10**3
def encode(value):
    return int(value * scale)
# 转换为仿射坐标系进行比较
def to_affine(point):
    if hasattr(point, 'to_affine'):
        return point.to_affine()
    return point

def sum_points(points_dict):
    # 初始化结果为无穷远点（即G * 0）
    result = curve.generator * 0  # 无穷远点
    # 遍历字典中的点并进行加法
    for point in points_dict.values():
        result += point  # 加法操作
    return result

def divide_point_by_number(point, number):
    # 计算 number 在曲线的有限域中的逆元素
    inverse_number = pow(number, -1, curve.order)  # 使用扩展欧几里得算法求逆
    # 对点进行标量乘法
    return inverse_number * point

def Ci(vector):
    return r * G + encode(sum(vector)) * G

def expected_C(num,vector_g):
    return (r + encode(sum(vector_g))) * G

def check(C_total, expected_C):
    C_total_affine = to_affine(C_total)
    expected_C_affine = to_affine(expected_C)
    return C_total_affine == expected_C_affine


# 基于种子生成随机多项式
def generate_a(size):
    rng = np.random.default_rng(seed_value)  # 伪随机数生成器
    return rng.integers(0, q, size)

def ci_compute(g):
    a_i = generate_a(len(g))
    e_i = np.random.randint(-5, 5, len(g))  # 噪声
    C_i = (a_i * g + e_i) % q
    return C_i, a_i, e_i

# Waiting time
# Set according to a target dropout rate (e.g., 1%) 
# and message lantecy (see model/LatencyModel.py)
wt_flamingo_report = pd.Timedelta('10s')
wt_flamingo_crosscheck = pd.Timedelta('3s')
wt_flamingo_reconstruction = pd.Timedelta('3s')

wt_google_adkey = pd.Timedelta('10s')
wt_google_graph = pd.Timedelta('10s')
wt_google_share = pd.Timedelta('30s')    # ensure all user_choice received messages
wt_google_collection = pd.Timedelta('10s')
wt_google_crosscheck = pd.Timedelta('3s')
wt_google_recontruction = pd.Timedelta('2s') 

# WARNING: 
# this should be a random seed from beacon service;
# we use a fixed one for simplicity
root_seed = get_random_bytes(32) 
nonce = b'\x00\x00\x00\x00\x00\x00\x00\x00'

def assert_power_of_two(x):
    return (math.ceil(math.log2(x)) == math.floor(math.log2(x)));

# choose committee members
def choose_committee(root_seed, committee_size, num_clients, group_type):
    
    prg_committee_holder = ChaCha20.new(key=root_seed, nonce=nonce)

    data = b"secr" * committee_size * 128 
    prg_committee_bytes = prg_committee_holder.encrypt(data)
    committee_numbers = np.frombuffer(prg_committee_bytes, dtype=vector_type)
        
    user_committee = set()
    cnt = 0
    while (len(user_committee) < committee_size):
        sampled_id = committee_numbers[cnt] % num_clients
        (user_committee).add(sampled_id + 1)
        cnt += 1

    if group_type == 1:
        user_committee = {x + num_clients for x in user_committee}
    return user_committee

# choose neighbors
def findNeighbors(root_seed, current_iteration, num_clients, id, neighborhood_size, group_type):
    if group_type == 1:
        id = id - num_clients

    neighbors_list = set() # a set, instead of a list

    # compute PRF(root, iter_num), output a seed. can use AES
    prf = ChaCha20.new(key=root_seed, nonce=nonce)
    current_seed = prf.encrypt(current_iteration.to_bytes(32, 'big')) 
  
    # compute PRG(seed), a binary string
    prg = ChaCha20.new(key=current_seed, nonce=nonce)
   
    # compute number of bytes we need for a graph
    num_choose = math.ceil(math.log2(num_clients))  # number of neighbors I choose
    num_choose = num_choose * neighborhood_size

    bytes_per_client = math.ceil(math.log2(num_clients) / 8)
    segment_len = num_choose * bytes_per_client
    num_rand_bytes = segment_len * num_clients
    data = b"a" * num_rand_bytes
    graph_string = prg.encrypt(data)

       
    # find the segment for myself
    my_segment = graph_string[(id - 1) *
                              segment_len: (id - 1) * (segment_len) + segment_len]

    # define the number of bits within bytes_per_client that can be convert to int (neighbor's ID)
    bits_per_client = math.ceil(math.log2(num_clients))
    # default number of clients is power of two
    for i in range(num_choose):
        tmp = my_segment[i*bytes_per_client: i *
                         bytes_per_client+bytes_per_client]
        tmp_neighbor = int.from_bytes(
            tmp, 'big') & ((1 << bits_per_client)-1)
            
        if tmp_neighbor == id - 1:
            # print("client", self.id, " random neighbor choice happened to be itself, skip")
            continue
        if tmp_neighbor in neighbors_list:
            # print("client", self.id, "already chose", tmp_neighbor, "skip")
            continue
        neighbors_list.add(tmp_neighbor)

    # now we have a list for who I chose
    # find my ID in the rest, see which segment I am in. add to neighbors_list
    for i in range(num_clients):
        if i == id - 1:
            continue
        seg = graph_string[i * segment_len: i *
                           (segment_len) + segment_len]
        ls = parse_segment_to_list(
            seg, num_choose, bits_per_client, bytes_per_client)
        if id - 1 in ls:
            # add current segment owner into neighbors_list
            neighbors_list.add(i)
    if group_type == 1:
        neighbors_list = [i + num_clients for i in neighbors_list]
    return neighbors_list

def parse_segment_to_list(segment, num_choose, bits_per_client, bytes_per_client):
    cur_ls = set()
    # take a segment (byte string), parse it to a list
    for i in range(num_choose):
        cur_bytes = segment[i*bytes_per_client: i *
                            bytes_per_client+bytes_per_client]
           
        cur_no = int.from_bytes(cur_bytes, 'big') & (
            (1 << bits_per_client)-1)
            
        cur_ls.add(cur_no)
        
    return cur_ls