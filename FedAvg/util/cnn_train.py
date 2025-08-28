import numpy as np
from tensorflow.keras.datasets import cifar100
from tensorflow.keras.models import Sequential, clone_model
from tensorflow.keras.layers import Conv2D, MaxPooling2D, Flatten, Dense
from tensorflow.keras.utils import to_categorical
from sklearn.utils import shuffle
from tqdm import tqdm

def build_cnn_model():
    model = Sequential([
        Conv2D(32, kernel_size=(3, 3), activation='relu', input_shape=(32, 32, 3)),
        MaxPooling2D(pool_size=(2, 2)),
        Conv2D(64, kernel_size=(3, 3), activation='relu'),
        MaxPooling2D(pool_size=(2, 2)),
        Flatten(),
        Dense(128, activation='relu'),
        Dense(100, activation='softmax')
    ])
    model.compile(optimizer='adam', loss='categorical_crossentropy', metrics=['accuracy'])
    return model


def get_model_weights(model):
    return model.get_weights()


def set_model_weights(model, weights):
    model.set_weights(weights)


def average_weights(weights_list):
    avg = []
    for weights in zip(*weights_list):
        avg.append(np.mean(weights, axis=0))
    return avg

def preprocess_and_split(num_clients=128):

    (X_train, y_train), (X_test, y_test) = cifar100.load_data(label_mode='fine')
    X_train = X_train.astype("float32") / 255.0
    X_test = X_test.astype("float32") / 255.0
    y_train_cat = to_categorical(y_train, 100)
    y_test_cat = to_categorical(y_test, 100)

    client_data = []
    client_size = len(X_train) // num_clients
    for i in range(num_clients):
        start, end = i * client_size, (i + 1) * client_size
        client_data.append((X_train[start:end], y_train_cat[start:end]))

    return client_data, (X_test, y_test_cat)

def federated_training(num_clients=128, num_rounds=20, num_epochs=1):
    client_data, (X_test, y_test_cat) = preprocess_and_split(num_clients)
    global_model = build_cnn_model()
    global_weights = get_model_weights(global_model)

    for rnd in range(num_rounds):
        print(f"\n--- Round {rnd + 1}/{num_rounds} ---")
        local_weights = []

        for client_idx in tqdm(range(num_clients), desc="Training clients"):
            local_model = build_cnn_model()
            set_model_weights(local_model, global_weights)

            X, y = client_data[client_idx]
            local_model.fit(X, y, epochs=num_epochs, verbose=0, batch_size=32)
            local_weights.append(get_model_weights(local_model))

            del local_model  # 节省内存

        # FedAvg 聚合
        global_weights = average_weights(local_weights)

        # 测试
        test_model = build_cnn_model()
        set_model_weights(test_model, global_weights)
        loss, acc = test_model.evaluate(X_test, y_test_cat, verbose=0)
        print(f"Test accuracy after round {rnd + 1}: {acc:.4f}")

if __name__ == "__main__":
    federated_training(num_clients=10, num_rounds=20, num_epochs=3)
