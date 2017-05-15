from flask import Flask, request, jsonify, abort
import redis
import uuid
import datetime


app = Flask(__name__)
app.config.update(dict(
    HOST='localhost',
    PORT=6379,
    DB=0
))


def get_redis():
    return redis.StrictRedis(host=app.config['HOST'],
                             port=app.config['PORT'],
                             db=app.config['DB'],
                             decode_responses=True)


def create_twiit(text, user_id=0):
    twiit_id = uuid.uuid4()
    get_redis().hmset(twiit_id,
                      {'id': twiit_id,
                       'user_id': user_id,
                       'text': text,
                       'created_at': datetime.datetime.utcnow()})
    return str(twiit_id)


def update_twiit(new_text, twiit_id):
    get_redis().hmset(twiit_id,
                      {'text': new_text,
                       'updated_at': datetime.datetime.utcnow()})
    return get_twiit(twiit_id)


def get_twiit(twiit_id):
    return get_redis().hgetall(twiit_id)


def delete_twiit(twiit_id):
    get_redis().delete(twiit_id)


@app.route('/')
def hello_world():
    return 'Hello World!'


@app.route('/twiit', methods=['POST', 'GET'])
def handle_create():
    if request.method == 'POST':
        twiit_id = create_twiit(request.form['text'])
        twiit = get_twiit(twiit_id)
        return jsonify(twiit)


@app.route('/twiit/<uuid:twiit_id>', methods=['GET', 'PUT', 'DELETE'])
def handle_twiit(twiit_id):
    twiit = get_twiit(twiit_id)
    if twiit:
        if request.method == 'GET':
            return jsonify(twiit)

        elif request.method == 'PUT':
            twiit = update_twiit(request.form['text'], twiit_id)
            return jsonify(twiit)

        elif request.method == 'DELETE':
            delete_twiit(twiit_id)
            return jsonify({'id': twiit_id, 'status': 'deleted'})
    else:
        abort(404)
