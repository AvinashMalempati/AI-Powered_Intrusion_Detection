from flask import Flask, jsonify
import pandas as pd

app = Flask(__name__)

@app.route("/alerts", methods=["GET"])
def alerts():
    df = pd.read_csv("results.csv")
    anomalies = df[df["Anomaly"] == "Anomaly"]
    return jsonify(anomalies.to_dict(orient="records"))

if __name__ == "__main__":
    app.run(debug=True, port=5000)

