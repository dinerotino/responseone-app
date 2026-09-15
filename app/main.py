from flask import Flask, request, jsonify

app = Flask(__name__)


@app.route("/")
def home():
    return jsonify({
        "application": "ResponseOne Demo Application",
        "status": "running"
    })


@app.route("/health")
def health():
    return jsonify({"status": "healthy"})


@app.route("/search")
def search():
    query = request.args.get("q", "")

    return jsonify({
        "query": query,
        "message": f"Search results for: {query}"
    })


@app.route("/api/user/<user_id>")
def get_user(user_id):
    return jsonify({
        "user_id": user_id,
        "username": "demo-user"
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
