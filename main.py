import os
import re
import json
import hashlib
import requests
import markdown2
from bs4 import BeautifulSoup
from collections import deque

import firebase_admin
from firebase_admin import credentials, db, auth
from googleapiclient.discovery import build

from langchain_core.messages import HumanMessage
from langchain_google_genai import ChatGoogleGenerativeAI

from markupsafe import escape
from flask import Flask, jsonify, request, send_file, send_from_directory, render_template, session, url_for, flash, redirect
from flask_session import Session

from dotenv import load_dotenv
#from db_handler import DBModule
from datetime import datetime
import traceback

load_dotenv('./auth/.env')

# Google Search API Key
api_key = os.environ.get('api_key')
cse_id = os.environ.get('cse_id')

# Gemini API Key
GOOGLE_API_KEY = os.environ.get('GOOGLE_API_KEY')

# Flask secret key
secret_key = os.environ.get('secret_key')

cred = credentials.Certificate('./auth/gnote-8e4ef-firebase-adminsdk-pbixg-49916beb00.json')

firebase_admin.initialize_app(cred,{
    'databaseURL':'https://gnote-8e4ef-default-rtdb.firebaseio.com/'
})

database = db.reference('/posts')

# Flask Settings
app = Flask(__name__)
app.secret_key = secret_key
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)

def sanitize_key(key):
    # Firebase Realtime Database에서 사용할 수 없는 문자를 삭제
    return re.sub(r'[$#\[\]/.]', '', key)

def google_search(query, api_key, cse_id, num_results=2):
    service = build("customsearch", "v1", developerKey=api_key)
    res = service.cse().list(q=query, cx=cse_id, num=num_results).execute()
    return res['items']

def fetch_page_content(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        return soup.get_text()
    except requests.exceptions.RequestException as e:
        print(f"Failed to fetch {url}: {e}")
        return ""

def extract_content_from_results(results):
    contents = []
    for item in results:
        title = item.get('title')
        link = item.get('link')
        page_content = fetch_page_content(link)
        clean_text = re.sub(r'\s+', ' ', page_content)
        contents.append(f"{clean_text}\n")
    return "\n\n".join(contents)


@app.route("/index2", methods=['GET', 'POST'])
def index2():
    return render_template('index2.html')

@app.route("/", methods=['GET'])
@app.route("/index", methods=['GET'])
def index():
    if 'GToken' in session :
        return render_template('index.html')
    else:
        return render_template('login.html')

@app.route("/gnote", methods=['GET'])
def GNote():
    try:
        public_data = db.reference('public_data').get()
    except Exception as e:
        return jsonify({"error": str(e)}), 400

    return render_template('gnote.html', public_data=public_data)

@app.route("/list", methods=['GET'])
def GNote_list():
    return render_template('list.html')

@app.route('/signup', methods=['POST'])
def signup():
    if request.method == "POST":
        email = request.form['email']
        password = request.form['password']

        try:
            if (email is not None) and (password is not None):
                user = auth.create_user(email=email, password=password)
                return render_template('login.html')

        except Exception as e:
            return jsonify({"error": str(e)}), 400

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'GToken' in session:
        return render_template('index.html')

    if request.method == "POST":
        email = request.form['email']
        password = request.form['password']

        if (email is None) or (password is None):
            return render_template('index.html')

        try:
            user = auth.get_user_by_email(email)

            headers = {'Content-Type': 'application/json'}
            payload = {
                "email": email,
                "password": password,
                "returnSecureToken": True
            }

            url = "https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=" + api_key

            # Firebase Authentication REST API를 사용하여 비밀번호 인증 시도
            response = requests.post(url, headers=headers, json=payload)
            
            # 응답 확인
            if response.status_code == 200:
                data = response.json()
                session['GToken'] = data['idToken']
                session['email'] = email

                print("비밀번호가 일치합니다.")
                return render_template('index.html')
            else:
                print("비밀번호가 일치하지 않습니다.")
                return render_template('login.html')
        
        except firebase_admin.auth.UserNotFoundError:
            print("해당 이메일의 사용자가 존재하지 않습니다.")
            return render_template('login.html')

    else:
        # GET Method
        return render_template('login.html')

@app.route('/logout', methods=['GET'])
def logout():
    if request.method == "GET":
        # 세션 종료
        session.pop('GToken', None)
        return render_template('login.html')

@app.route('/verify-token', methods=['GET','POST'])
def verify_token():
    try:
        token = session['GToken']
        decoded_token = auth.verify_id_token(token)
        return jsonify({"message": "Token is valid", "uid": decoded_token['uid']}), 200

    except Exception as e:
        return jsonify({"message": str(e)}), 400

@app.route('/send_verification_email', methods=['GET', 'POST'])
def send_verification_email():
    if request.method == "POST":
        if request.form['email'] == None :
            return render_template('signup.html')

        try:
            email = request.form['email']
            user = auth.get_user_by_email(email)
            link = auth.generate_email_verification_link(email)
            # 이메일 발송 로직 추가 (예: SendGrid, SMTP 등 사용)
            return jsonify({"message": "Verification email sent", "link": link}), 200

        except Exception as e:
            return jsonify({"error": str(e)}), 400

@app.route('/reset_password', methods=['POST'])
def reset_password():
    if request.method == "POST":
        if request.form['email'] == None :
            return render_template('reset_password.html')
    try:
        email = request.form['email']
        link = auth.generate_password_reset_link(email)
        # 이메일 발송 로직 추가 (예: SendGrid, SMTP 등 사용)
        return jsonify({"message": "Password reset email sent", "link": link}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/search', methods=['GET','POST'])
def search():
    if request.method == "GET":
        return render_template("search.html")
    elif request.method == "POST":
        if request.form['search']:
            search = request.form['search']
            return render_template("search_result.html", search=search)

@app.route('/view', methods=['GET', 'POST'])
def view():
    if request.method == "GET":
        return render_template("view.html")
    else:
        if request.form['id'] :
            article_id = request.form['id']
            return render_template("view.html", id=article_id)

@app.route("/write", methods=['GET', 'POST'])
def Write():
    return render_template('write.html')

@app.route("/ai_write", methods=['GET', 'POST'])
def ai_write():
    return render_template('ai_write.html')

@app.route('/posts', methods=['GET'])
def get_pots():
    try:
        posts = database.get()

        if posts is None:
            posts = []
        else:
            posts = list(posts.values())
        posts.sort(key=lambda x: x['timestamp'], reverse=True)
        return jsonify(posts), 200

    except Exception as e:
        print(traceback.format_exc())
        return f"An Error Occurred: {e}", 500

@app.route('/posts/<post_id>', methods=['GET'])
def posts_link(post_id):
    try:
        post = database.child(post_id).get()

        if not post :
            return f"Post with ID {post_id} not found", 404
        else:
            return jsonify(posts), 200

    except Exception as e:
        print(traceback.format_exc())
        return f"An Error Occurred: {e}", 500

@app.route('/posts', methods=['POST'])
def add_post():
    try:
        data = request.json
        print('Post Method posts data : ', data)
        data['timestamp'] = datetime.now().isoformat()
        data['likes'] = 0
        data['shares'] = 0
        new_post_ref = database.push(data)
        data['id'] = new_post_ref.key
        new_post_ref.set(data)
        return jsonify(data), 201

    except Exception as e:
        print(traceback.format_exc())
        return f"An Error Occurred: {e}", 500

@app.route('/posts/<post_id>', methods=['PUT'])
def edit_post(post_id):
    try:
        data = request.json
        post_ref = database.child(post_id)
        post_ref.update(data)
        return jsonify(data), 200

    except Exception as e:
        print(traceback.format_exc())
        return f"An Error Occurred: {e}", 500

@app.route('/posts/<post_id>', methods=['DELETE'])
def delete_post(post_id):
    try:
        post_ref = database.child(post_id)
        post_ref.delete()
        return '', 204
    except Exception as e:
        print(traceback.format_exc())
        return f"An Error Occurred: {e}", 500

@app.route('/posts/<post_id>/like', methods=['POST'])
def like_post(post_id):
    try:
        post_ref = database.child(post_id).child('likes')
        post_ref.transaction(lambda likes: (likes or 0) + 1)
        return jsonify({"success": True}), 200

    except Exception as e:
        print(traceback.format_exc())
        return f"An Error Occurred: {e}", 500

@app.route('/posts/<post_id>/share', methods=['POST'])
def share_post(post_id):
    try:
        post_ref = database.child(post_id).child('shares')
        post_ref.transaction(lambda shares: (shares or 0) + 1)
        return jsonify({"success": True}), 200

    except Exception as e:
        print(traceback.format_exc())
        return f"An Error Occurred: {e}", 500

@app.route("/category", methods=['POST'])
def show_category():
    if request.method == "POST":
        category = request.form.get('category')

        if category is not None :
            category = escape(category)
        else:
            return render_template('index.html')
        
        # realtime database
        # ref = db.reference('/')
        # print(ref.get()['test'])

        ref = db.reference(category)
        ref.update({'flask' : 'x0x'})
        return render_template('index.html', category=category)

@app.route("/api/generate", methods=["POST"])
def generate_api():
    if 'idToken' in session:
        # verify token
        return render_template('index.html')

    if request.method == "POST":
        try:
            data = deque()
            req_body = request.get_json()
            content = req_body.get("contents")
            query = content[0]['text']
            #query = escape(query)

            # Fetch search results
            search_results = google_search(query, api_key, cse_id)
                
            # Extract and combine content
            search_result = extract_content_from_results(search_results)

            model = ChatGoogleGenerativeAI(model=req_body.get("model"))

            message = HumanMessage(
                content = "Please organize the contents below carefully and print them within 3000 characters. Remove all sentences that are not related to the question : " + query + "\n\n" + search_result
            )
            
            response = model.stream([message])

            def stream():
                for chunk in response:
                    
                    yield '%s\n\n' % json.dumps({ "text":chunk.content })
                    data.append(chunk.content)

                result = ''.join(data)
                #print("store realtime database : ", result)
                ref = db.reference('public_data').child(sanitize_key(query)).set(result)

            return stream(), {'Content-Type': 'text/event-stream'}

        except Exception as e:
            return jsonify({ "error": str(e) })

# @app.route('/<path:path>')
# def serve_static(path):
#     return send_from_directory('templates', path)

@app.route('/mynote/<post_id>', methods=['GET'])
def article_link(post_id):
    try:
        #post = database.child(post_id).get()
        user = auth.get_user_by_email(session['email'])
        data = db.reference(f'users/{user.uid}/').get()

        if not post :
            return f"Post with ID {post_id} not found", 404
        else:
            return jsonify(posts), 200

    except Exception as e:
        print(traceback.format_exc())
        return f"An Error Occurred: {e}", 500

@app.route('/mynote', methods=['GET','POST'])
def add_article():
    try:
        data = request.json
        print('Post Method posts data : ', data)
        data['timestamp'] = datetime.now().isoformat()
        user = auth.get_user_by_email(session['email'])
        data = db.reference(f'users/{user.uid}/').get()
        return jsonify(data), 201

    except Exception as e:
        print(traceback.format_exc())
        return f"An Error Occurred: {e}", 500

@app.route('/mynote/<post_id>', methods=['PUT'])
def edit_article(post_id):
    try:
        data = request.json
        post_ref = database.child(post_id)
        post_ref.update(data)
        return jsonify(data), 200

    except Exception as e:
        print(traceback.format_exc())
        return f"An Error Occurred: {e}", 500

@app.route('/mynote/<post_id>', methods=['DELETE'])
def delete_article(post_id):
    try:
        post_ref = database.child(post_id)
        post_ref.delete()
        return '', 204
    except Exception as e:
        print(traceback.format_exc())
        return f"An Error Occurred: {e}", 500

@app.route('/get_personal_data', methods=['GET', 'POST'])
def get_personal_data():
    if request.method == "GET":
        if 'GToken' in session:
            try:
                user = auth.get_user_by_email(session['email'])
                data = db.reference(f'users/{user.uid}/').get()

                # If there's no article
                if data == None :
                    return render_template('test.html')

                personal_data = []

                for key, val in data.items():
                    print('{0} : {1}'.format(key, val))
                    personal_data.append(val['content'])

                return render_template('test.html', private_data=personal_data)

            except Exception as e:
                return jsonify({"error": str(e)}), 400
        else:
            return render_template('login.html')

@app.route('/save_personal_data', methods=['POST'])
def save_personal_data():
    if request.method == "POST":
        data = request.json

        if ('GToken' in session) and (data != None):
            try:
                user = auth.get_user_by_email(session['email'])
                db.reference(f'users/{user.uid}/').push(data)
                return render_template('test.html')
            except Exception as e:
                return jsonify({"error": str(e)}), 400
        else:
            return render_template('login.html')

@app.route('/save_public_data', methods=['POST'])
def save_public_data():
    if request.method == "POST":
        data = request.form['data']

        try:
            db.reference('public_data').push(data)
            return jsonify({"message": "Public data saved successfully"}), 200

        except Exception as e:
            return jsonify({"error": str(e)}), 400

@app.route('/get_public_data', methods=['GET'])
def get_public_data():
    try:
        public_data = db.reference('public_data').get()
        return render_template('index.html', public_data=public_data)

    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/settings", methods=['GET', 'POST'])
def settings():
    if request.method == "GET":
        return render_template('settings.html')
    elif request.method == "POST":
        print("user id: ", user.uid)
        personal_data = db.reference(f'users/{user.uid}/settings').get()
        return render_template('settings.html', settings=settings)

@app.route("/health")
def health_check():
    return 'ok'

if __name__ == "__main__":
    app.run('0.0.0.0', port=5000, debug=True)
