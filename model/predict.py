import numpy as np
import pandas as pd
import pickle
from tensorflow.keras.models import load_model

# ==== USER INPUT SECTION ====
# Replace values here to test different scenarios
user_input = {
    'network_packet_size': 1500,
    'protocol_type': 'TCP',
    'login_attempts': 2,
    'session_duration': 3600,
    'encryption_used': 'AES',
    'ip_reputation_score': 0.9,
    'failed_logins': 5,
    'browser_type': 'Chrome',
    'unusual_time_access': 1
}

# ==== LOAD SAVED MODELS & ENCODERS ====
model = load_model("cnn_trust_model.h5")

with open("protocol_type_label_encoder.pkl", "rb") as f:
    protocol_encoder = pickle.load(f)

with open("encryption_used_label_encoder.pkl", "rb") as f:
    encryption_encoder = pickle.load(f)

with open("browser_type_label_encoder.pkl", "rb") as f:
    browser_encoder = pickle.load(f)

with open("scaler.pkl", "rb") as f:
    scaler = pickle.load(f)

# ==== ENCODE CATEGORICAL INPUT ====
def encode_input(data):
    data['protocol_type'] = protocol_encoder.transform([data['protocol_type']])[0]
    data['encryption_used'] = encryption_encoder.transform([data['encryption_used']])[0]
    data['browser_type'] = browser_encoder.transform([data['browser_type']])[0]
    return data

encoded_input = encode_input(user_input.copy())

# ==== CONVERT TO DF, SCALE, RESHAPE ====
df_input = pd.DataFrame([encoded_input])
scaled_input = scaler.transform(df_input)
reshaped_input = scaled_input.reshape(scaled_input.shape[0], scaled_input.shape[1], 1)

# ==== PREDICTION ====
prediction = model.predict(reshaped_input)[0][0]
label = " Wormhole Detected!" if prediction > 0.5 else " Normal Activity"
print(f"\nPrediction Score: {prediction:.4f} => {label}")
