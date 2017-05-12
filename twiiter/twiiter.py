from flask import Flask, g, request, jsonify
import redis
import uuid
import time


app = Flask(__name__)
app.config.update(dict(
    HOST='localhost',
    PORT=6379,
    DB=0
))


def get_redis():
    if not hasattr(g, 'redis'):
        g.redis = redis.StrictRedis(host=app.config['HOST'],
                                    port=app.config['PORT'],
                                    db=app.config['DB'],
                                    decode_responses=True)

    return g.redis


def create_twiit(status, user_id=0):
    twiit_id = uuid.uuid4()
    get_redis().hmset(twiit_id,
                      {'user_id': user_id,
                       'status': status,
                       'timestamp': time.time(),
                       'formatted_timestamp': time.ctime()}
                      )
    return str(twiit_id)


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
        twiit_id = create_twiit(request.form['status'])
        return twiit_id


@app.route('/twiit/<uuid:twiit_id>', methods=['GET', 'DELETE'])
def handle_twiit(twiit_id):
    if request.method == 'GET':
        return jsonify(get_twiit(twiit_id))
    elif request.method == 'DELETE':
        delete_twiit(twiit_id)
        return '%s deleted' % twiit_id
