import numpy as np
import pandas as pd
import tensorflow as tf
import os
from keras import layers, models, losses
from upload.Thesis.analysis.utilities import uncompress

MAX_FILESIZE = 40000
IMAGE_SHAPE = int(np.sqrt(MAX_FILESIZE))
TRAIN_PROC = 0.8
SCALE = 100000
tf.get_logger().setLevel('ERROR')


class ConstrainedLoss(losses.Loss):
    def __init__(self, base_loss):
        super(ConstrainedLoss, self).__init__()
        self.base_loss = base_loss

    def call(self, y_true, y_pred):
        # Compute the base loss (e.g., mean squared error)
        base_loss_value = self.base_loss(y_true, y_pred)

        # Compute the penalty for constraint violation
        constraint_penalty = tf.reduce_sum(tf.nn.relu(y_pred[:, 0] - y_pred[:, 1]))

        # Return the combined loss
        return base_loss_value + constraint_penalty


class VulnerabilityScanner:

    def __init__(self, load_weights=True, model_location="upload/Thesis/model_checkpoints/epoch_14.keras"):
        self.model = self.create_cnn_rnn_model()
        if load_weights:
            self.model.load_weights(model_location)

    def binary_to_input(self, path):
        with open(path, "rb") as f:
            content = f.read()
        data = np.frombuffer(content, dtype=np.uint8)[:MAX_FILESIZE]
        data = data / 255.0
        data = np.pad(data, (0, MAX_FILESIZE - len(data)), 'constant', constant_values=-1)
        return data.reshape(IMAGE_SHAPE, IMAGE_SHAPE, 1)

    def create_cnn_rnn_model(self, input_shape=(IMAGE_SHAPE, IMAGE_SHAPE, 1), num_bounding_boxes=5):
        # CNN for feature extraction
        model = models.Sequential([
            # CNN for feature extraction
            layers.Input(shape=input_shape),
            layers.Conv2D(32, (3, 3), activation='relu', input_shape=input_shape),
            layers.MaxPooling2D((2, 2)),
            layers.Dropout(0.25),
            layers.Conv2D(64, (3, 3), activation='relu'),
            layers.MaxPooling2D((2, 2)),
            layers.Dropout(0.25),
            layers.Conv2D(128, (3, 3), activation='relu'),
            layers.MaxPooling2D((2, 2)),
            layers.Dropout(0.25),
            layers.Flatten(),

            # Expand dimensions for RNN input
            layers.Reshape((1, -1)),

            # RNN for sequence prediction
            layers.Bidirectional(layers.LSTM(128, return_sequences=True)),
            layers.Bidirectional(layers.LSTM(64, return_sequences=False)),

            # Fully connected layers for bounding boxes and confidence scores
            layers.Dense(256, activation='relu'),
            layers.Dense(128, activation='relu'),
            layers.Dense(num_bounding_boxes * 3, activation='sigmoid'),
            layers.Reshape((num_bounding_boxes, 3))
        ])

        base_loss = losses.MeanSquaredError()
        model.compile(optimizer='adam', loss=ConstrainedLoss(base_loss))

        return model

    def readFile(self, filename):
        with open(filename, "rb") as f:
            return f.read()

    def split_validation(self, labels, features):
        training_len = int(TRAIN_PROC * len(features))
        training_x = features[:training_len]
        training_y = labels[:training_len]

        validation_x = features[training_len:]
        validation_y = labels[training_len:]

        return (training_x, training_y), (validation_x, validation_y)

    def prepare_train_data(self, inputs_path, expected_outputs):
        labels = pd.read_csv(expected_outputs)
        labels = labels.fillna(0)
        labels = labels.sample(frac=1)
        features = labels.pop("filename")

        labels = np.array(labels)

        features = [self.binary_to_input(os.path.join("generated/generated_compressed", file + ".zip")) for file in
                    features]

        features = np.array(features)
        labels = labels.reshape((-1, 1, 5, 3))

        (x_train, y_train), (x_test, y_test) = self.split_validation(features, labels)

        return (x_train, y_train), (x_test, y_test)

    def train_model(self, train_dataset, epochs=20, batch_size=2):
        checkpoint_path = "model_checkpoints/epoch_{epoch:02d}.keras"

        # Define the ModelCheckpoint callback
        checkpoint_callback = tf.keras.callbacks.ModelCheckpoint(
            filepath=checkpoint_path,
            save_freq='epoch',  # Save every epoch
            save_best_only=False,  # Save all checkpoints, not just the best
            save_weights_only=False,  # Save the full model (architecture + weights)
            verbose=1  # Print when saving a model
        )

        # self.model.compile(optimizer='adam', loss='mse')
        x_train = train_dataset[1]
        y_train = train_dataset[0]
        # print(x_train.shape)
        # print(y_train.shape)
        self.model.fit(x_train, y_train, epochs=epochs, callbacks=[checkpoint_callback], batch_size=1)

    def eval_performance(self, validation_dataset):
        self.model.evaluate(validation_dataset[1], validation_dataset[0], verbose=2)

    def predict_bounding_boxes(self, filepath, verbose='auto'):
        print(f"Predicting '{filepath}' vulnerabilities...")
        print(f"Size: {os.path.getsize(filepath) / 1024:.2f}KB")
        print("=============================")
        data = self.binary_to_input(filepath)
        data = data.reshape(-1, IMAGE_SHAPE, IMAGE_SHAPE, 1)
        predictions = self.model.predict(data, verbose=verbose)

        return predictions

    def get_vulns(self, zip_path, verbose='auto'):
        filepath = uncompress(zip_path)
        predictions = self.predict_bounding_boxes(filepath, verbose=verbose)
        predictions = [[int(s1 * SCALE), int(e1 * SCALE), c] for s1, e1, c in predictions[0]]
        return predictions

    def print_vulns(self, zip_path):
        predictions = self.get_vulns(zip_path)
        for s1, e1, c in predictions:
            print(f"Found vuln between 0x{s1:x} - 0x{e1:x} | {c * 100:.2f}%")


# Example usage
# file_path = 'path_to_your_binary_file.bin'
# batches = preprocess_binary_file(file_path)


if __name__ == '__main__':
    model = VulnerabilityScanner()
    # Assuming train_data and train_labels are available for training
    # train_model(model, train_data, train_labels)

    # Make predictions
    # predictions = model.predict_bounding_boxes("generated/generated_compressed/empty1.zip")
    # predictions = model.print_vulns("generated/generated_compressed/vul3.zip")
    # print(predictions)
    (x_train, y_train), (x_test, y_test) = model.prepare_train_data("generated/generated_compressed", "outputs.csv")
    model.train_model((x_train, y_train))
# model.eval_performance((x_test, y_test))
