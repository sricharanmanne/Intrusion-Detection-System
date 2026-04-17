# Intrusion Detection System (IDS)

A Flask-based web application that leverages a trained CNN model to detect wormhole attacks and classify network activity as **Normal Activity** or **Wormhole Detected!**. The system stores predictions in an SQLite database and provides visualization of detection trends.

---

## 🚀 Features
- **Web Interface**: User-friendly form for submitting network parameters.
- **Deep Learning Model**: CNN (`cnn_trust_model.h5`) for intrusion detection.
- **Preprocessing**: Label encoders and scaler for consistent input handling.
- **Database Integration**: SQLite database (`predictions.db`) stores prediction history.
- **Visualization**:
  - Pie chart of detection results.
  - Line chart of prediction scores over time.
- **History Page**: Review past predictions with all input parameters and outcomes.

---

## 🛠️ Tech Stack
- **Backend**: Python, Flask
- **Machine Learning**: TensorFlow/Keras, Scikit-learn
- **Database**: SQLite
- **Frontend**: HTML (Jinja2 templates)
- **Visualization**: Matplotlib

---

## 📂 Project Structure
App/
│── app.py                  # Main Flask application
│── model/                  # Saved CNN model & encoders
│   ├── cnn_trust_model.h5
│   ├── protocol_type_label_encoder.pkl
│   ├── encryption_used_label_encoder.pkl
│   ├── browser_type_label_encoder.pkl
│   └── scaler.pkl
│── templates/              # HTML templates
│   ├── index.html
│   ├── history.html
│   └── predicted_accuracy.html
│── predictions.db          # SQLite database (auto-created)

---

## ⚙️ Setup Instructions

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/Intrusion-Detection-System.git
   cd Intrusion-Detection-System/App

-------------------------------------------------------------------------------------------
Create a virtual environment (recommended):
python -m venv venv
source venv/bin/activate   # On Linux/Mac
venv\Scripts\activate      # On Windows
-------------------------------------------------------------------------------------------
Install dependencies:
pip install -r requirements.txt
Example requirements.txt:
Code
Flask
numpy
pandas
tensorflow
scikit-learn
matplotlib
------------------------------------------------------------------------------------------
Run the application:
python app.py
