from flask import Flask, request, jsonify
import joblib
import numpy as np

app = Flask(__name__)

pipeline = joblib.load(r"D:\PROJECTS\FYRP_IDS\models\pipeline.pkl")
le = joblib.load(r"D:\PROJECTS\FYRP_IDS\models\label_encoder.pkl")

@app.route("/predict", methods=["POST"])
def predict():
    try:
        data = request.json['features']

        data = np.array(data).reshape(1, -1)

        pred = pipeline.predict(data)[0]
        label = le.inverse_transform([pred])[0]

        return jsonify({"prediction": label})

    except Exception as e:
        return jsonify({"error": str(e)})

if __name__ == "__main__":
    app.run(debug=True)

