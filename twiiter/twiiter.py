# -*- coding: utf-8 -*-
from flask import Flask, request, jsonify, abort, session, redirect, url_for, \
        render_template, g
from flask_oauthlib.client import OAuth
from jinja2 import evalcontextfilter, Markup
import redis
import boto3
import datetime
import string
import random
import re


app = Flask(__name__)
app.config.from_pyfile('../oauth.cfg')
app.config.from_pyfile('../s3.cfg')
ALLOWED_EXTENSIONS = set(['jpg', 'jpeg'])
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


s3 = boto3.resource(
    service_name='s3',
    endpoint_url='http://localhost:4569',
    region_name=app.config['REGION_NAME'],
    aws_access_key_id=app.config['AWS_ACCESS_KEY_ID'],
    aws_secret_access_key=app.config['AWS_SECRET_ACCESS_KEY']
)


s3_client = boto3.client(
    service_name='s3',
    endpoint_url='http://localhost:4569',
    region_name=app.config['REGION_NAME'],
    aws_access_key_id=app.config['AWS_ACCESS_KEY_ID'],
    aws_secret_access_key=app.config['AWS_SECRET_ACCESS_KEY']
)


def show_buckets():
    buckets = {}
    for bucket in s3.buckets.all():
        buckets[bucket.name] = []
        for item in bucket.objects.all():
            buckets[bucket.name].append(item.key)
    return buckets


def get_redis():
    return redis.StrictRedis(host=app.config['HOST'],
                             port=app.config['PORT'],
                             db=app.config['DB'],
                             decode_responses=True)


def id_generator(size=5):
    chars = string.ascii_letters+string.digits
    return ''.join(random.SystemRandom().choice(chars) for _ in range(size))


def valid_image(image_file):
    return image_file.content_type == 'image/jpeg'


def allowed_file(filename):
    return '.' in filename and \
            filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def save_user_data(data):
    data['last_login'] = datetime.datetime.utcnow()
    get_redis().hmset('user:{}'.format(data['id']), data)
    get_redis().lpush('users', data['id'])


def upload_image(image_file):
    image_id = id_generator()
    while (get_redis().exists('image:{}'.format(image_id))):
        # generate new id until no collide
        image_id = id_generator()
    key = '{}.jpg'.format(image_id)
    s3_client.upload_fileobj(image_file, 'imageBucket', key)
    get_redis().lpush('images', image_id)
    return image_id


def delete_image(image_id):
    resp = s3_client.delete_object(
            Bucket='imageBucket',
            Key='{}.jpg'.format(image_id))
    get_redis().lrem('images', 1, image_id)
    app.logger.info(resp)


def create_twiit(text, user_id, image_file):
    twiit_id = id_generator()
    while (get_redis().exists('twiit:{}'.format(twiit_id))):
        # generate new id until no collide
        twiit_id = id_generator()
    get_redis().hmset('twiit:{}'.format(twiit_id),
                      {'id': twiit_id,
                       'user_id': user_id,
                       'text': text,
                       'created_at': datetime.datetime.utcnow()})
    if image_file and valid_image(image_file):
        image_id = upload_image(image_file)
        key = '{}.jpg'.format(image_id)
        url = s3_client.generate_presigned_url('get_object',
                                               Params={
                                                   'Bucket': 'imageBucket',
                                                   'Key': key},
                                               ExpiresIn=604800)  # 7 Days
        get_redis().hmset('twiit:{}'.format(twiit_id),
                          {'image_id': image_id,
                           'image_url': url})

    get_redis().lpush('timeline', twiit_id)
    return twiit_id


def update_twiit(new_text, twiit_id):
    get_redis().hmset('twiit:{}'.format(twiit_id),
                      {'text': new_text,
                       'updated_at': datetime.datetime.utcnow()})


def get_twiit(twiit_id):
    return get_redis().hgetall('twiit:{}'.format(twiit_id))


def delete_twiit(twiit_id):
    twiit = get_twiit(twiit_id)
    if 'image_id' in twiit:
        delete_image(twiit['image_id'])
    get_redis().delete('twiit:{}'.format(twiit_id))
    get_redis().lrem('timeline', 1, twiit_id)


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


def get_users(start, end):
    users = []
    for user_id in get_redis().lrange('users', start, end):
        user = get_redis().hgetall('user:{}'.format(user_id))
        users.append(user)
    return users


def get_user(user_id):
    return get_redis().hgetall('user:{}'.format(user_id))


@app.template_filter()
@evalcontextfilter
def linebreaks(eval_ctx, value):
    """Converts newlines into <p> and <br />s."""
    value = re.sub(r'\r\n|\r|\n', '\n', value)  # normalize newlines
    value = re.sub(' ', '&nbsp;', value)  # preserve spaces in html
    paras = re.split('\n{2,}', value)
    paras = [u'<p>%s</p>' % p.replace('\n', '<br />') for p in paras]
    paras = u'\n\n'.join(paras)
    return Markup(paras)


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
        create_twiit(request.form['text'],
                     g.user['id'],
                     request.files['image-file'])
        return redirect(url_for('index'))
    else:
        abort(401)


@app.route('/twiit/<twiit_id>', methods=['GET', 'PUT', 'DELETE'])
def handle_twiit(twiit_id):
    twiit = get_twiit(twiit_id)
    if twiit:
        if request.method == 'GET':
            return jsonify(twiit)

        # PUT and DELETE requires authorization
        elif g.user and g.user['id'] == twiit['user_id']:
            if request.method == 'PUT':
                twiit = update_twiit(request.form['text'],
                                     twiit_id)
                return jsonify(twiit)

            elif request.method == 'DELETE':
                delete_twiit(twiit_id)
                return jsonify({'msg': 'deleted'})
        else:
            abort(401)
    else:
        abort(404)


@app.route('/twiits', methods=['GET'])
def handle_twiits():
    return jsonify(get_twiits(0, 100))


@app.route('/users', methods=['GET'])
def handle_users():
    return jsonify(get_users(0, 100))


@app.route('/check_buckets')
def check_s3():
    return jsonify(show_buckets())


@app.route('/reset_dbs')
def reset():
    for key in s3.Bucket('imageBucket').objects.all():
        key.delete()

    get_redis().flushdb()
    return 'All databases reset'
