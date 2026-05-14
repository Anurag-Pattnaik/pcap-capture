from fastapi import FastAPI
from pydantic import BaseModel
import joblib
import numpy as np
from pymongo import MongoClient
from datetime import datetime

# =========================
# INIT APP
# =========================
app = FastAPI()

# =========================
# LOAD MODELS
# =========================
binary_model = joblib.load(r"models\binary_pipeline.pkl")
attack_model = joblib.load(r"models\attack_pipeline.pkl")

le_binary = joblib.load(r"models\binary_label_encoder.pkl")
le_attack = joblib.load(r"models\attack_label_encoder.pkl")

# =========================
# DB CONNECTION
# =========================
client = MongoClient("mongodb+srv://mishrarohan3181_db_user:4JJNwQQrPHaUMhNN@clusterfyrp.ubcp87k.mongodb.net/?retryWrites=true&w=majority")
db = client["ids_db"]
collection = db["logs"]

# =========================
# REQUEST FORMAT
# =========================
class InputData(BaseModel):
    features: list
ATTACK_THRESHOLD = 55.0 
# =========================
# PREDICT ENDPOINT
# =========================
@app.post("/predict")
def predict(data: InputData):

    try:
        raw = data.features

        feature_names = [
            'dst_port', 'protocol', 'flow_duration', 'total_packets',
            'total_bytes', 'min_pkt_len', 'max_pkt_len', 'avg_pkt_len',
            'pkt_len_std', 'flow_rate', 'iat', 'syn_flag',
            'ack_flag', 'rst_flag', 'psh_flag', 'ttl'
        ]

        x = dict(zip(feature_names, raw))

        # =========================
        # FEATURE ENGINEERING
        # =========================
        x['bytes_per_packet'] = x['total_bytes'] / (x['total_packets'] + 1e-6)
        x['packets_per_second'] = x['total_packets'] / (x['flow_duration'] + 1e-6)
        x['flag_sum'] = (
            x['syn_flag'] +
            x['ack_flag'] +
            x['rst_flag'] +
            x['psh_flag']
        )
        x['avg_packet_size'] = x['total_bytes'] / (x['total_packets'] + 1e-6)

        x['byte_rate'] = x['total_bytes'] / (x['flow_duration'] + 1e-6)

        x['burstiness'] = x['pkt_len_std'] / (x['avg_pkt_len'] + 1e-6)
        final_features = np.array(list(x.values())).reshape(1, -1)

        # =========================
        # BINARY
        # =========================
        binary_pred = binary_model.predict(final_features)[0]
        binary_label = le_binary.inverse_transform([binary_pred])[0]

        binary_conf = float(np.max(binary_model.predict_proba(final_features)) * 100)

        # =========================
        # BENIGN CASE
        # =========================
        if binary_label == "BENIGN":

            result = {
                "prediction": "SAFE",
                "threat": "None",
                "confidence": round(binary_conf, 2),
                "timestamp": str(datetime.now())
            }

            collection.insert_one(dict(result))   # ✅ FIX
            return dict(result)                  # ✅ FIX

        # =========================
        # ATTACK CASE
        # =========================
        attack_pred = attack_model.predict(final_features)[0]
        attack_label = le_attack.inverse_transform([attack_pred])[0]

        attack_conf = float(np.max(attack_model.predict_proba(final_features)) * 100)

        if attack_conf < ATTACK_THRESHOLD:

            result = {
                "prediction": "SAFE",
                "threat": "SUSPICIOUS",
                "confidence": round(attack_conf, 2),
                "timestamp": str(datetime.now())
            }

        else:

            result = {
                "prediction": "MALICIOUS",
                "threat": attack_label,
                "confidence": round(attack_conf, 2),
                "timestamp": str(datetime.now())
            }

        collection.insert_one(dict(result))   # ✅ FIX
        return dict(result)                  # ✅ FIX

    except Exception as e:
        return {"error": str(e)}

# =========================
# GET LOGS
# =========================
@app.get("/logs")
def get_logs():
    logs = []
    for doc in collection.find():
        doc["_id"] = str(doc["_id"])
        logs.append(doc)
    return logs