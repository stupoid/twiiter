# -*- coding: utf-8 -*-
from flask import Flask, request, jsonify, abort, session, redirect, url_for, \
        render_template, g, Response
from flask_oauthlib.client import OAuth
from jinja2 import evalcontextfilter, Markup
import redis
import boto3
import datetime
import time
import string
import random
import re
import requests

development = True

app = Flask(__name__)
app.config.from_pyfile('../google-oauth.cfg')
app.config.from_pyfile('../facebook-oauth.cfg')
app.config.from_pyfile('../s3.cfg')
app.config.from_pyfile('../redis.cfg')


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


facebook = oauth.remote_app(
    'facebook',
    base_url='https://graph.facebook.com/',
    request_token_url=None,
    access_token_url='/oauth/access_token',
    authorize_url='https://www.facebook.com/dialog/oauth',
    consumer_key=app.config['FACEBOOK_APP_ID'],
    consumer_secret=app.config['FACEBOOK_APP_SECRET'],
    request_token_params={
        'scope': ['public_profile', 'email']
    }
)

if development:
    s3 = boto3.resource(
        service_name='s3',
        endpoint_url='http://localhost:4569',
        region_name=app.config['AWS_REGION_NAME'],
        aws_access_key_id=app.config['AWS_ACCESS_KEY_ID'],
        aws_secret_access_key=app.config['AWS_SECRET_ACCESS_KEY']
    )

    s3_client = boto3.client(
        service_name='s3',
        endpoint_url='http://localhost:4569',
        region_name=app.config['AWS_REGION_NAME'],
        aws_access_key_id=app.config['AWS_ACCESS_KEY_ID'],
        aws_secret_access_key=app.config['AWS_SECRET_ACCESS_KEY']
    )

    if s3.Bucket('interns-kelvin') not in s3.buckets.all():
        s3.create_bucket(Bucket='interns-kelvin')

else:
    s3 = boto3.resource('s3')
    s3_client = boto3.client('s3')


def show_buckets():
    buckets = {}
    for bucket in s3.buckets.all():
        buckets[bucket.name] = []
        for item in bucket.objects.all():
            buckets[bucket.name].append(item.key)
    return buckets


def get_redis():
    return redis.StrictRedis(host=app.config['REDIS_HOST'],
                             port=app.config['REDIS_PORT'],
                             db=app.config['REDIS_DB'],
                             decode_responses=True)


def get_user_data():
    data = None
    if 'facebook_token' in session:
        data = facebook.get('/me?fields=id,name,email,' +
                            'picture.height(320).width(320),locale').data
        if 'picture' in data:
            data['picture'] = data['picture']['data']['url']
    elif 'google_token' in session:
        data = google.get('userinfo').data

    if data:
        if 'error' in data:
            session.pop('google_token', None)
            session.pop('facebook_token', None)
            data = None
        elif get_redis().exists('user:{}'.format(data['id'])):
            data['twiits'] = get_redis().zcount('twiited:{}'.format(data['id']),
                                                0, '+inf')
            data['followers'] = get_redis().zcount('followers:{}'.format(data['id']),
                                                   0, '+inf')
            data['following'] = get_redis().zcount('following:{}'.format(data['id']),
                                                   0, '+inf')
        else:
            save_user_data(data)

    return data


def id_generator(size):
    chars = string.ascii_letters+string.digits
    return ''.join(random.SystemRandom().choice(chars) for _ in range(size))


def new_id(key, size=5):
    id_string = id_generator(size)
    # Check for collision
    while (get_redis().exists('{}:{}'.format(key, id_string))):
        id_string = id_generator()
    return id_string


def save_user_data(data):
    data['last_login'] = datetime.datetime.utcnow()
    if not get_redis().exists('user:{}'.format(data['id'])):
        data['created_on'] = datetime.datetime.utcnow()
        get_redis().sadd('users', data['id'])
    get_redis().hmset('user:{}'.format(data['id']), data)


def upload_image(image_file):
    image_id = new_id('image')
    key = '{}.jpg'.format(image_id)
    s3_client.upload_fileobj(image_file, 'interns-kelvin', key)
    url = s3_client.generate_presigned_url('get_object', Params={
                                               'Bucket': 'interns-kelvin',
                                               'Key': key},
                                               ExpiresIn=60)  # 1 Min
    app.logger.info(url)
    get_redis().zadd('images', time.time(), image_id)
    get_redis().hmset('image:{}'.format(image_id),
                      {'id': image_id,
                       'url': url,
                       'created_at': time.time()})
    return image_id


def refresh_image_url(image_id):
    url = s3_client.generate_presigned_url('get_object', Params={
                                               'Bucket': 'interns-kelvin',
                                               'Key': '{}.jpg'.format(image_id)},
                                               ExpiresIn=60) # 1 Min
    get_redis().hmset('image:{}'.format(image_id),
                      {'url': url,
                       'created_at': time.time()})
    return url


def get_image_url(image_id):
    image = get_redis().hgetall('image:{}'.format(image_id))
    url = image['url']
    if time.time() - float(image['created_at']) >= 60:
        app.logger.info('get new url')
        url = refresh_image_url(image_id)
    return url


def valid_image_id(image_id):
    return get_redis().exists('image:{}'.format(image_id))


def delete_image(image_id):
    resp = s3_client.delete_object(
            Bucket='interns-kelvin',
            Key='{}.jpg'.format(image_id))
    get_redis().delete('image:{}'.format(image_id))
    get_redis().zrem('images', image_id)
    app.logger.info(resp)


def add_tag(tag, twiit_id):
    get_redis().zadd('tag:{}'.format(tag), time.time(), twiit_id)


def remove_tag(tag, twiit_id):
    get_redis().zrem('tag:{}'.format(tag), twiit_id)


def create_twiit(text, user_id, image_file):
    twiit_id = new_id('twiit')
    tags = set(re.findall(r'(?i)(?<=\#)\w+', text))
    for tag in tags:
        add_tag(tag, twiit_id)

    get_redis().hmset('twiit:{}'.format(twiit_id),
                      {'id': twiit_id,
                       'user_id': user_id,
                       'text': text,
                       'tags': ', '.join(tags),
                       'created_at': datetime.datetime.utcnow()})
    if image_file and image_file.content_type == 'image/jpeg':
        image_id = upload_image(image_file)
        get_redis().hmset('twiit:{}'.format(twiit_id), {'image_id': image_id})

    # keep track of user twiits
    get_redis().zadd('twiited:{}'.format(user_id), time.time(), twiit_id)
    get_redis().zadd('timeline', time.time(), twiit_id)
    return twiit_id


def edit_twiit(twiit_id, new_text):
    tags = get_twiit(twiit_id)['tags'].split(', ')
    for tag in tags:
        remove_tag(tag, twiit_id)

    new_tags = set(re.findall(r'(?i)(?<=\#)\w+', new_text))
    for new_tag in new_tags:
        add_tag(new_tag, twiit_id)

    get_redis().hmset('twiit:{}'.format(twiit_id),
                      {'text': new_text,
                       'tags': ', '.join(new_tags),
                       'updated_at': datetime.datetime.utcnow()})


def get_twiit(twiit_id):
    return get_redis().hgetall('twiit:{}'.format(twiit_id))


def delete_twiit(twiit_id):
    twiit = get_twiit(twiit_id)
    if 'image_id' in twiit:
        delete_image(twiit['image_id'])

    tags = get_twiit(twiit_id)['tags'].split(', ')
    for tag in tags:
        remove_tag(tag, twiit_id)
    get_redis().delete('twiit:{}'.format(twiit_id))
    get_redis().zrem('twiited:{}'.format(g.user['id']), twiit_id)
    get_redis().zrem('timeline',  twiit_id)


def get_twiits(max_score, min_score='-inf', limit=5, user_id=None, tag=None):
    key = 'timeline'

    if tag:
        key = 'tag:{}'.format(tag)
    elif user_id:
        key = 'timeline:{}'.format(user_id)
        following = get_redis().zrange('following:{}'.format(user_id), 0, -1)
        following.append(user_id)
        following = ['twiited:{}'.format(following_id)
                     for following_id in following]
        get_redis().zunionstore(key, following)

    twiits_data = {}
    twiits = []
    # zrevrange for DESC
    # for twiit_id in get_redis().zrevrange(key, 0, 100):
    last_score = float('inf')
    latest_score = 0
    for twiit_id in get_redis().zrevrangebyscore(key, max_score, min_score, 0, limit, True):
        if twiit_id[1] < last_score:
            last_score = twiit_id[1]
        if twiit_id[1] > latest_score:
            latest_score = twiit_id[1]
        twiit = get_redis().hgetall('twiit:{}'.format(twiit_id[0]))
        twiit['user'] = get_user(twiit['user_id'])
        twiits.append(twiit)
    twiits_data['last_score'] = last_score
    twiits_data['latest_score'] = latest_score
    twiits_data['data'] = twiits
    return twiits_data


def get_users():
    users = []
    following = []
    if g.user:
        following = get_following(g.user['id'])
    for user_id in get_redis().smembers('users'):
        user = get_user(user_id)
        if user['id'] in following:
            user['is_following'] = True
        users.append(user)
    return users


def get_following(user_id):
    return get_redis().zrange('following:{}'.format(user_id), 0, -1)


def get_followers(user_id):
    return get_redis().zrange('followers:{}'.format(user_id), 0, -1)


def get_user(user_id):
    user = dict(zip(['email', 'name', 'picture', 'id'],
                    get_redis().hmget('user:{}'.format(user_id),
                                      'email', 'name', 'picture', 'id')))
    user['twiits'] = get_redis().zcount('twiited:{}'.format(user_id),
                                        0, '+inf')
    user['followers'] = get_redis().zcount('followers:{}'.format(user_id),
                                           0, '+inf')
    user['following'] = get_redis().zcount('following:{}'.format(user_id),
                                           0, '+inf')
    return user


def delete_user(user_id):
    for twiit_id in get_redis().zrange('twiited:{}'.format(user_id), 0, -1):
        delete_twiit(twiit_id)

    for follower_id in get_followers(user_id):
        get_redis().zrem('following:{}'.format(follower_id), user_id)

    for following_id in get_following(user_id):
        get_redis().zrem('followers:{}'.format(following_id), user_id)

    get_redis().delete('following:{}'.format(user_id))
    get_redis().delete('followers:{}'.format(user_id))
    get_redis().delete('twiited:{}'.format(user_id))
    get_redis().delete('user:{}'.format(user_id))
    get_redis().srem('users', user_id)
    session.pop('google_token', None)
    session.pop('facebook_token', None)


def follow(follower_id, following_id):
    # following:id => users that id is currently following
    # followers:id => users that are following id
    # unix time is used as score to sort the set
    get_redis().zadd('following:{}'.format(follower_id),
                     time.time(),
                     following_id)
    get_redis().zadd('followers:{}'.format(following_id),
                     time.time(),
                     follower_id)


def unfollow(follower_id, following_id):
    get_redis().zrem('following:{}'.format(follower_id), following_id)
    get_redis().zrem('followers:{}'.format(following_id), follower_id)


@app.template_filter()
@evalcontextfilter
def linebreaks(eval_ctx, value):
    """Converts newlines into <p> and <br />s."""
    value = re.sub(r'\r\n|\r|\n', '\n', value)  # normalize newlines
    value = re.sub(' ', '&nbsp;', value)  # preserve spaces in html
    for hashtag in set(re.findall(r'#\w+', value)):
        tag = hashtag[1:]
        value = re.sub(hashtag, '<a href="/tag/{}">{}</a>'.format(tag, hashtag), value)

    paras = re.split('\n{2,}', value)
    paras = [u'<p>%s</p>' % p.replace('\n', '<br />') for p in paras]
    paras = u'\n\n'.join(paras)
    return Markup(paras)


@app.before_request
def before_request():
    g.user = get_user_data()


@google.tokengetter
def get_google_oauth_token():
    return session.get('google_token')


@facebook.tokengetter
def get_facebook_oauth_token():
    return session.get('facebook_token')


@app.route('/')
def index():
    if g.user:
        max_score = request.args.get('max_score') or time.time()
        limit = request.args.get('limit') or 5
        twiits_data = get_twiits(max_score, '-inf', limit, g.user['id'])
        return render_template('index.html',
                               twiits=twiits_data['data'],
                               last_score=twiits_data['last_score'],
                               last_updated=twiits_data['latest_score'])
    else:
        return redirect(url_for('global_timeline'))


@app.route('/global')
def global_timeline():
    max_score = request.args.get('max_score') or time.time()
    limit = request.args.get('limit') or 5
    twiits_data = get_twiits(max_score, '-inf', limit)
    return render_template('index.html',
                           twiits=twiits_data['data'],
                           last_score=twiits_data['last_score'],
                           last_updated=twiits_data['latest_score'],
                           global_timeline=True)


@app.route('/tag/<tag>')
def tag_timeline(tag):
    if re.fullmatch('\w+', tag):
        max_score = request.args.get('max_score') or time.time()
        limit = request.args.get('limit') or 5
        twiits_data = get_twiits(max_score, '-inf', limit, None, tag)
        return render_template('index.html',
                               twiits=twiits_data['data'],
                               last_score=twiits_data['last_score'],
                               last_updated=twiits_data['latest_score'],
                               tag=tag)
    else:
        abort(400)


@app.route('/login-facebook')
def login_facebook():
    if not development:
        return facebook.authorize(callback='http://kelvin.aws.prd.demodesu.com/login-facebook/authorized')
    else:
        return facebook.authorize(callback=url_for('facebook_authorized',
                                  next=request.args.get('next')
                                  or request.referrer
                                  or None,
                                  _external=True))


@app.route('/login-google')
def login_google():
    if not development:
        return google.authorize(callback='http://kelvin.aws.prd.demodesu.com/login-google/authorized')
    else:
        return google.authorize(callback=url_for('authorized_google',
                                _external=True))


@app.route('/logout')
def logout():
    session.pop('google_token', None)
    session.pop('facebook_token', None)
    return redirect(url_for('index'))


@app.route('/login-google/authorized')
def authorized_google():
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


@app.route('/login-facebook/authorized')
def facebook_authorized():
    resp = facebook.authorized_response()
    if resp is None:
        return 'Access denied: reason=%s error=%s' % (
            request.args['error_reason'],
            request.args['error_description']
        )
    session['facebook_token'] = (resp['access_token'], '')
    data = get_user_data()
    save_user_data(data)
    return redirect(url_for('index'))


@app.route('/twiit', methods=['POST'])
def handle_create():
    if g.user:
        text = request.form['text']
        app.logger.info(len(re.sub('\r\n', ' ', text)))
        if len(text) <= 130:
            twiit_id = create_twiit(text,
                                    g.user['id'],
                                    request.files['image-file'])
            twiit = get_twiit(twiit_id)
            twiit['user'] = get_user(twiit['user_id'])
            return jsonify(twiit)
        else:
            abort(400)
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
                edit_twiit(twiit_id, request.form['text'])
                twiit = get_twiit(twiit_id)
                twiit['user'] = get_user(twiit['user_id'])
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
    max_score = request.args.get('max_score') or time.time()
    max_score = float(max_score)

    min_score = request.args.get('min_score') or '-inf'
    if min_score != '-inf':
        min_score = float(min_score)

    limit = request.args.get('limit') or 5
    tag = request.args.get('tag') or None

    user_id = request.args.get('user_id') or None
    if not g.user or user_id != g.user['id']:
        user_id = None

    twiits_data = get_twiits(max_score, min_score, limit, user_id, tag)
    if not twiits_data['data']:
        twiits_data['last_score'] = 0

    return jsonify(twiits_data)


@app.route('/users', methods=['GET'])
def handle_users():
    return render_template('users.html', users=get_users())


@app.route('/user/<user_id>', methods=['GET', 'DELETE'])
def handle_user(user_id):
    if request.method == 'GET':
        user = get_user(user_id)
        if g.user and g.user['id'] != user_id:
            user['is_following'] = user_id in get_following(g.user['id'])
        return jsonify(user)
    elif request.method == 'DELETE':
        delete_user(user_id)
        return jsonify({'msg': 'deleted'})


@app.route('/follow/<int:user_id>', methods=['POST'])
def handle_follow(user_id):
    if g.user and g.user['id'] != user_id:
        follow(g.user['id'], user_id)
        return redirect(url_for('handle_users'))
    else:
        abort(400)


@app.route('/unfollow/<int:user_id>', methods=['POST'])
def handle_unfollow(user_id):
    if g.user and g.user['id'] != user_id:
        unfollow(g.user['id'], user_id)
        return redirect(url_for('handle_users'))
    else:
        abort(400)


@app.route('/image/<image_id>', methods=['GET'])
def route_image(image_id):
    if valid_image_id(image_id):
        req = requests.get(get_image_url(image_id),
                           stream=True, params=request.args)
        def generate():
            for chunk in req.iter_content(1024):
                yield chunk
        return Response(generate(), headers={'Content-Type': 'image/jpeg'})
    else:
        abort(404)


@app.route('/check_buckets')
def check_s3():
    return jsonify(show_buckets())


@app.route('/reset_dbs')
def reset():
    for key in s3.Bucket('interns-kelvin').objects.all():
        key.delete()

    get_redis().flushdb()
    return 'All databases reset'
