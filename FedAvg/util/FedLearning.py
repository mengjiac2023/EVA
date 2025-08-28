import numpy as np
from sklearn.datasets import make_classification
from sklearn.neural_network import MLPClassifier
from sklearn.model_selection import train_test_split

def create_model(warm_start=False):
    model = MLPClassifier(warm_start=warm_start)
    return model

def flatten_model(model):
    return np.concatenate([w.ravel() for w in model.coefs_] + [b.ravel() for b in model.intercepts_])

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
    model.n_iter_ = int(np.round(flat_vector[0]))
    model.n_layers_ = int(np.round(flat_vector[1]))
    model.n_outputs_ = int(np.round(flat_vector[2]))
    model.t_ = int(np.round(flat_vector[3]))

    param_vector = flat_vector[7:]
    shapes = [w.shape for w in model.coefs_] + [b.shape for b in model.intercepts_]
    sizes = [np.prod(s) for s in shapes]
    chunks = np.split(param_vector, np.cumsum(sizes)[:-1])

    model.coefs_ = [chunks[i].reshape(shapes[i]) for i in range(len(model.coefs_))]
    model.intercepts_ = [chunks[i + len(model.coefs_)].reshape(shapes[i + len(model.coefs_)])
                         for i in range(len(model.intercepts_))]
    return model
