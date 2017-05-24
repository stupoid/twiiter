# Twiiter
A simple twitter clone using flask and redis


### Features Implemented

- [x] Twiiting (POST/DELETE/PUT): Storing message to KVS
- [x] Attaching images: Storing image files to S3
- [x] Single Sign-On Authentication using Google Account
- [x] Single Sign-On Authentication using Facebook Account
- [x] Following/followers
- [x] Hashtags
- [x] Infinitescroll to retrieve past twiits
- [x] Automatic polling of new twiits on current timeline
- [x] Image passthrough from S3 without exposing S3 link (to automatically update expiry)

### ~ How to use

1. install the app from the root of the project directory

    `pip install --editable .`

2. instruct flask to use the right application

    `export FLASK_APP=twiiter`

3. now you can run twiiter:

    `flask run`

    access the application at
    http://localhost:5000/
