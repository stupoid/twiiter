from flask import Flask, request, jsonify, abort, session, redirect, url_for, render_template, g
from flask_oauthlib.client import OAuth
import redis
import uuid
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
    consumer_key=app.config.get('GOOGLE_ID'),
    consumer_secret=app.config.get('GOOGLE_SECRET'),
    request_token_params={
        'scope': 'email'
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


@app.before_request
def before_request():
    g.user = None
    if 'google_token' in session:
        g.user = google.get('userinfo').data
        app.logger.info(g.user)


@google.tokengetter
def get_google_oauth_token():
    return session.get('google_token')


@app.route('/')
def index():
    return render_template('index.html')


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
    g.user = google.get('userinfo').data
    app.logger.info(g.user)
    return redirect(url_for('index'))
#    return jsonify({"data": g.user.data})


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
