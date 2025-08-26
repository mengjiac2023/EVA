import numpy as np
from sklearn.datasets import make_classification
from sklearn.neural_network import MLPClassifier
from sklearn.model_selection import train_test_split

# 创建公共模型结构
def create_model(warm_start=False):
    model = MLPClassifier(warm_start=warm_start)
    return model

# 展平模型参数
def flatten_model(model):
    return np.concatenate([w.ravel() for w in model.coefs_] + [b.ravel() for b in model.intercepts_])

# 从向量恢复模型参数
def unflatten_model(model, flat_vector):
    shapes = [w.shape for w in model.coefs_] + [b.shape for b in model.intercepts_]
    sizes = [np.prod(s) for s in shapes]
    chunks = np.split(flat_vector, np.cumsum(sizes)[:-1])
    coefs = [chunks[i].reshape(shapes[i]) for i in range(len(model.coefs_))]
    intercepts = [chunks[i + len(model.coefs_)].reshape(shapes[i + len(model.coefs_)]) for i in range(len(model.intercepts_))]
    model.coefs_ = coefs
    model.intercepts_ = intercepts
    return model

def flatten_model_with_state(model):
    state_vector = np.array([
        model.n_iter_,
        model.n_layers_,
        model.n_outputs_,
        model.t_,
        model._no_improvement_count,
        model.loss_,
        model.best_loss_
    ], dtype=np.float32)

    flat_weights = np.concatenate(
        [w.ravel() for w in model.coefs_] +
        [b.ravel() for b in model.intercepts_]
    )

    return np.concatenate([state_vector, flat_weights])

def unflatten_model_with_state(model, flat_vector):
    # 仅使用前 4 个元数据字段
    model.n_iter_ = int(np.round(flat_vector[0]))
    model.n_layers_ = int(np.round(flat_vector[1]))
    model.n_outputs_ = int(np.round(flat_vector[2]))
    model.t_ = int(np.round(flat_vector[3]))

    # 后面是 coefs_ 和 intercepts_
    param_vector = flat_vector[7:]  # 跳过全部 7 个状态字段
    shapes = [w.shape for w in model.coefs_] + [b.shape for b in model.intercepts_]
    sizes = [np.prod(s) for s in shapes]
    chunks = np.split(param_vector, np.cumsum(sizes)[:-1])

    model.coefs_ = [chunks[i].reshape(shapes[i]) for i in range(len(model.coefs_))]
    model.intercepts_ = [chunks[i + len(model.coefs_)].reshape(shapes[i + len(model.coefs_)])
                         for i in range(len(model.intercepts_))]
    return model

# # 初始化数据
# X, y = make_classification(n_samples=1000, n_features=20, n_classes=2, random_state=42)
# classes = np.unique(y)
# client_data = [train_test_split(X, y, test_size=0.8, random_state=i)[:2] for i in range(5)]
#
# # 初始化服务器模型，用于确定参数维度
# tmp_model = create_model()
# tmp_model.partial_fit(X[:10], y[:10], classes=classes)
# param_len = len(flatten_model(tmp_model))
#
# # 初始化服务器参数向量
# server_param = flatten_model(tmp_model)
#
# # 联邦训练
# for rnd in range(5):
#     print(f"\n📡 Round {rnd+1}")
#     client_params = []
#
#     for client_id, (Xc, yc) in enumerate(client_data):
#         # 客户端每次新建模型
#         local_model = create_model()
#         local_model.partial_fit(X[:10], y[:10], classes=classes)  # 初始化结构
#         unflatten_model(local_model, server_param)  # 载入全局参数
#         local_model.partial_fit(Xc, yc)  # 本地训练
#         vec = flatten_model(local_model)
#         client_params.append(vec)
#         print(f"  ✅ Client {client_id} sent vector of length {len(vec)}")
#
#     # 服务器聚合
#     server_param = np.mean(client_params, axis=0)
#     print("  🔄 Server aggregated vectors.")
#
# # 评估
# X_test, y_test = make_classification(n_samples=300, n_features=20, n_classes=2, random_state=123)
# test_model = create_model()
# test_model.partial_fit(X[:10], y[:10], classes=classes)
# unflatten_model(test_model, server_param)
# acc = test_model.score(X_test, y_test)
# print(f"\n🎯 Final accuracy: {acc:.4f}")
