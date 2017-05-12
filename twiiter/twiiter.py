from flask import Flask, request, jsonify
import uuid


app = Flask(__name__)


@app.route('/')
def hello_world():
    return 'Hello World!'
