from flask import Flask, render_template, request, redirect, url_for
import numpy as np
import pandas as pd
import pickle
import sqlite3
from tensorflow.keras.models import load_model
import os

app = Flask(__name__)

# ==== Load Model & Encoders ====
model = load_model("model/cnn_trust_model.h5")
with open("model/protocol_type_label_encoder.pkl", "rb") as f:
    protocol_encoder = pickle.load(f)
with open("model/encryption_used_label_encoder.pkl", "rb") as f:
    encryption_encoder = pickle.load(f)
with open("model/browser_type_label_encoder.pkl", "rb") as f:
    browser_encoder = pickle.load(f)
with open("model/scaler.pkl", "rb") as f:
    scaler = pickle.load(f)

# ==== Label Mappings ====
protocol_map = {'ICMP': 0, 'TCP': 1, 'UDP': 2}
encryption_map = {'AES': 0, 'DES': 1, 'Unknown': 2}
browser_map = {'Chrome': 0, 'Edge': 1, 'Firefox': 2, 'Safari': 3, 'Unknown': 4}

# ==== Ensure SQLite DB Exists ====
def init_db():
    conn = sqlite3.connect('predictions.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS predictions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    network_packet_size INTEGER,
                    protocol_type TEXT,
                    login_attempts INTEGER,
                    session_duration INTEGER,
                    encryption_used TEXT,
                    ip_reputation_score REAL,
                    failed_logins INTEGER,
                    browser_type TEXT,
                    unusual_time_access INTEGER,
                    prediction_score REAL,
                    result TEXT
                )''')
    conn.commit()
    conn.close()

init_db()

# ==== Encode & Predict ====
def encode_input(data):
    data['protocol_type'] = protocol_encoder.transform([data['protocol_type']])[0]
    data['encryption_used'] = encryption_encoder.transform([data['encryption_used']])[0]
    data['browser_type'] = browser_encoder.transform([data['browser_type']])[0]
    return data

def predict_and_save(user_input):
    encoded = encode_input(user_input.copy())
    df = pd.DataFrame([encoded])
    scaled = scaler.transform(df)
    reshaped = scaled.reshape(scaled.shape[0], scaled.shape[1], 1)
    prediction = model.predict(reshaped)[0][0]
    result = "Wormhole Detected!" if prediction > 0.5 else "Normal Activity"
    
    # Save to DB
    conn = sqlite3.connect('predictions.db')
    c = conn.cursor()
    c.execute('''INSERT INTO predictions (
                    network_packet_size, protocol_type, login_attempts, session_duration,
                    encryption_used, ip_reputation_score, failed_logins,
                    browser_type, unusual_time_access, prediction_score, result
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''', (
                    user_input['network_packet_size'],
                    user_input['protocol_type'],
                    user_input['login_attempts'],
                    user_input['session_duration'],
                    user_input['encryption_used'],
                    user_input['ip_reputation_score'],
                    user_input['failed_logins'],
                    user_input['browser_type'],
                    user_input['unusual_time_access'],
                    float(prediction),
                    result
                ))
    conn.commit()
    conn.close()

    return prediction, result

# ==== Routes ====
@app.route('/', methods=['GET', 'POST'])
def index():
    prediction = None
    result = None
    if request.method == 'POST':
        user_input = {
            'network_packet_size': int(request.form['network_packet_size']),
            'protocol_type': request.form['protocol_type'],
            'login_attempts': int(request.form['login_attempts']),
            'session_duration': int(request.form['session_duration']),
            'encryption_used': request.form['encryption_used'],
            'ip_reputation_score': float(request.form['ip_reputation_score']),
            'failed_logins': int(request.form['failed_logins']),
            'browser_type': request.form['browser_type'],
            'unusual_time_access': int(request.form['unusual_time_access']),
        }
        prediction, result = predict_and_save(user_input)

    return render_template('index.html',
                           protocol_map=protocol_map,
                           encryption_map=encryption_map,
                           browser_map=browser_map,
                           prediction=prediction,
                           result=result)

@app.route('/history')
def history():
    conn = sqlite3.connect('predictions.db')
    conn.row_factory = sqlite3.Row  
    c = conn.cursor()
    c.execute("SELECT * FROM predictions ORDER BY id DESC")
    rows = c.fetchall()
    conn.close()
    return render_template('history.html', records=rows)

import matplotlib.pyplot as plt
import io
import base64

@app.route('/predicted_accuracy')
def predicted_accuracy():
    conn = sqlite3.connect('predictions.db')
    c = conn.cursor()
    
    # Fetch result counts for pie chart
    c.execute("SELECT result, COUNT(*) FROM predictions GROUP BY result")
    counts = dict(c.fetchall())

    # Fetch scores for line chart
    c.execute("SELECT id, prediction_score FROM predictions ORDER BY id")
    trend_data = c.fetchall()
    conn.close()

    # Pie Chart
    pie_labels = list(counts.keys())
    pie_sizes = list(counts.values())
    fig1, ax1 = plt.subplots()
    ax1.pie(pie_sizes, labels=pie_labels, autopct='%1.1f%%', startangle=90)
    ax1.axis('equal')
    pie_buf = io.BytesIO()
    plt.savefig(pie_buf, format='png')
    pie_buf.seek(0)
    pie_chart = base64.b64encode(pie_buf.getvalue()).decode('utf-8')
    plt.close()

    # Line Chart
    ids = [row[0] for row in trend_data]
    scores = [row[1] for row in trend_data]
    fig2, ax2 = plt.subplots()
    ax2.plot(ids, scores, marker='o')
    ax2.set_title("Prediction Score Over Time")
    ax2.set_xlabel("Prediction ID")
    ax2.set_ylabel("Score")
    line_buf = io.BytesIO()
    plt.savefig(line_buf, format='png')
    line_buf.seek(0)
    line_chart = base64.b64encode(line_buf.getvalue()).decode('utf-8')
    plt.close()

    return render_template('predicted_accuracy.html',
                           pie_chart=pie_chart,
                           line_chart=line_chart)



if __name__ == '__main__':
    app.run(debug=True)
