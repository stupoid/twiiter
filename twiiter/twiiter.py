from flask import Flask, request, jsonify, abort, session, redirect, url_for, \
        render_template, g
from flask_oauthlib.client import OAuth
import redis
import datetime


app = Flask(__name__)
app.config.from_pyfile('../oauth.cfg')
app.config.update(dict(
    HOST='localhost',
    PORT=6379,
    DB=0
))


app.debug = True
app.secret_key = 'development'
oauth = OAuth(app)


google = oauth.remote_app(
    'google',
    consumer_key=app.config['GOOGLE_ID'],
    consumer_secret=app.config['GOOGLE_SECRET'],
    request_token_params={
        'scope': ['profile', 'email']
    },
    base_url='https://www.googleapis.com/oauth2/v1/',
    request_token_url=None,
    access_token_method='POST',
    access_token_url='https://accounts.google.com/o/oauth2/token',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
)


def get_redis():
    return redis.StrictRedis(host=app.config['HOST'],
                             port=app.config['PORT'],
                             db=app.config['DB'],
                             decode_responses=True)


def save_user_data(data):
    data['last_login'] = datetime.datetime.utcnow()
    app.logger.info(data)
    get_redis().hmset('user:'+data['id'], data)


def create_twiit(text, user_id):
    twiit_id = get_redis().incr('next_twiit_id')
    get_redis().hmset('twiit:{}'.format(twiit_id),
                      {'id': twiit_id,
                       'user_id': user_id,
                       'text': text,
                       'created_at': datetime.datetime.utcnow()})
    get_redis().lpush('timeline', twiit_id)
    return twiit_id


def update_twiit(new_text, twiit_id):
    get_redis().hmset(twiit_id,
                      {'text': new_text,
                       'updated_at': datetime.datetime.utcnow()})


def get_twiit(twiit_id):
    return get_redis().hgetall('twiit:{}'.format(twiit_id))


def delete_twiit(twiit_id):
    get_redis().delete(twiit_id)


def get_twiits(start, end, user_id=-1):
    if user_id == -1:
        key = 'timeline'
    else:
        key = 'user:{}'.format(user_id)

    twiits = []

    for twiit_id in get_redis().lrange(key, start, end):
        twiit = get_redis().hgetall('twiit:{}'.format(twiit_id))
        twiit['user'] = get_user(twiit['user_id'])
        twiits.append(twiit)

    return twiits


def get_user(user_id):
    return get_redis().hgetall('user:{}'.format(user_id))


@app.before_request
def before_request():
    g.user = None
    if 'google_token' in session:
        data = google.get('userinfo').data
        if 'error' in data:  # When session still has expired token
            session.pop('google_token', None)
        else:
            g.user = data


@google.tokengetter
def get_google_oauth_token():
    return session.get('google_token')


@app.route('/')
def index():
    return render_template('index.html', twiits=get_twiits(0, 100))


@app.route('/login')
def login():
    return google.authorize(callback=url_for('authorized', _external=True))


@app.route('/logout')
def logout():
    session.pop('google_token', None)
    return redirect(url_for('index'))


@app.route('/login/authorized')
def authorized():
    resp = google.authorized_response()
    if resp is None:
        return 'Access denied: reason=%s error=%s' % (
            request.args['error_reason'],
            request.args['error_description']
        )
    session['google_token'] = (resp['access_token'], '')
    data = google.get('userinfo').data
    save_user_data(data)
    return redirect(url_for('index'))


@app.route('/twiit', methods=['POST'])
def handle_create():
    if g.user:
        twiit_id = create_twiit(request.form['text'], g.user['id'])
        twiit = get_twiit(twiit_id)
        return jsonify(twiit)
    else:
        abort(401)


@app.route('/twiit/<int:twiit_id>', methods=['GET', 'PUT', 'DELETE'])
def handle_twiit(twiit_id):
    twiit = get_twiit(twiit_id)
    if twiit:
        if request.method == 'GET':
            return jsonify(twiit)

        elif g.user:  # PUT and DELETE requires authorization
            if request.method == 'PUT':
                twiit = update_twiit(request.form['text'],
                                     twiit_id,
                                     g.user['id'])
                return jsonify(twiit)

            elif request.method == 'DELETE':
                delete_twiit(twiit_id)
                return jsonify({'id': twiit_id, 'status': 'deleted'})
        else:
            abort(401)
    else:
        abort(404)


@app.route('/twiits', methods=['GET'])
def handle_twiits():
    return jsonify(get_twiits(0, 100))
