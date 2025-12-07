from flask import Flask, render_template, request, abort, jsonify
import psycopg2
import logging
import jwt
import datetime
from functools import wraps
import os
from dotenv import load_dotenv
import bcrypt

load_dotenv()

logger = logging.getLogger(__name__)
app = Flask(__name__)

SECRET_KEY = os.getenv('SECRET_KEY', 'fallback-secret-key-for-development')
DATABASE_NAME = os.getenv('DATABASE_NAME')
DATABASE_USER = os.getenv('DATABASE_USER')
DATABASE_PASSWORD = os.getenv('DATABASE_PASSWORD')
DATABASE_HOST = os.getenv('DATABASE_HOST')
DATABASE_PORT = os.getenv('DATABASE_PORT')
TOKEN_ALGORITHM = os.getenv('TOKEN_ALGORITHM')
APP_HOST = os.getenv('APP_HOST')
APP_PORT = os.getenv('APP_PORT')

class User:

    def __init__(self, login, password, user_order):
        self.login = login
        self.password = password
        self.user_order = user_order


def get_connection():
    connection = psycopg2.connect(database=DATABASE_NAME, user=DATABASE_USER,
                                  password=DATABASE_PASSWORD, host=DATABASE_HOST, port=DATABASE_PORT)
    cursor = connection.cursor()

    return connection, cursor


def close_connection(conn, cur):
    conn.close()
    cur.close()

def create_token(user_id, secret_key):
    payload = {
        'user_id': user_id,
        'exp': datetime.datetime.now(datetime.UTC) + datetime.timedelta(minutes=60),
    }
    token = jwt.encode(payload, secret_key, algorithm=TOKEN_ALGORITHM)
    return token

def hash_password(password: str) -> str:
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return bcrypt.checkpw(
            plain_password.encode('utf-8'),
            hashed_password.encode('utf-8')
        )
    except Exception:
        return False

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')

        if not token:
            print("ERROR: Token is missing")
            return jsonify(success=False, message='Token is missing'), 401

        try:
            if token.startswith('Bearer '):
                token = token[7:]

            data = jwt.decode(token, SECRET_KEY, algorithms=[TOKEN_ALGORITHM])
            current_user_id = data['user_id']
            print(f"Token validated for user: {current_user_id}")

        except jwt.ExpiredSignatureError:
            print("ERROR: Token expired")
            return jsonify(success=False, message='Token has expired'), 401
        except jwt.InvalidTokenError:
            print("ERROR: Invalid token")
            return jsonify(success=False, message='Invalid token'), 401

        return f(current_user_id, *args, **kwargs)

    return decorated

@app.route('/')
@app.route('/index')
def index():
    return render_template('index.html')

@app.route('/register', methods=['POST'])
def create_user_mob():
    json = request.json

    if not json or 'login' not in json or 'password' not in json:
        return jsonify(success=False, message='Missing required fields: login and password'), 400

    login = json['login']
    password = json['password']
    email = "none"

    if not login or not password:
        return jsonify(success=False, message='Login and password cannot be empty'), 400

    if len(login) < 3 or len(login) > 32:
        return jsonify(success=False, message='Login must be between 3 and 32 characters'), 400

    if len(password) < 6 or len(password) > 32:
        return jsonify(success=False, message='Password must be between 6 and 32 characters'), 400

    connection, cursor = get_connection()
    try:

        hashed_password = hash_password(password)
        cursor.execute('''INSERT INTO USERS(username, userpassword, usermail)
                                VALUES (%s, %s, %s)''', (login, hashed_password, email))
        connection.commit()
        print(f'User {login} successfully created', login, hashed_password, email)

        return jsonify(success=True, message='User created successfully'), 200

    except psycopg2.IntegrityError:
        return jsonify(success=False, message='Login already exists'), 400

    except psycopg2.OperationalError as e:
        logger.error(f"Database connection error: {e}")
        return jsonify(success=False, message='Database temporarily unavailable'), 503

    except psycopg2.Error as e:
        logger.error(f"Database error: {e}")
        return jsonify(success=False, message='Internal database error'), 500

    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        return jsonify(success=False, message='Internal server error'), 500

    finally:
        close_connection(connection, cursor)


@app.route('/login', methods=['POST'])
def login_user():
    if not request.is_json:
        print("ERROR: Request is not JSON")
        return jsonify(success=False, message='Content-Type must be application/json'), 400

    json = request.json

    if not json:
        print("ERROR: No JSON data received")
        return jsonify(success=False, message='No JSON data received'), 400

    if 'login' not in json or 'password' not in json:
        print("ERROR: Missing login or password field")
        return jsonify(success=False, message='Missing required fields: login and password'), 400

    login = json['login']
    password = json['password']

    print(f"Processing login: login='{login}'")

    if not login or not password:
        print("ERROR: Empty login or password")
        return jsonify(success=False, message='Login and password cannot be empty'), 400

    connection, cursor = get_connection()
    try:
        cursor.execute('''SELECT username, userpassword FROM USERS WHERE username = %s''', (login,))
        user_data = cursor.fetchone()

        if user_data:
            user_name = user_data[0]
            stored_hashed_password = user_data[1]

            if verify_password(password, stored_hashed_password):
                print(f"SUCCESS: User {user_name} authenticated")

                # Создаем JWT токен
                token = create_token(user_name, SECRET_KEY)

                return jsonify(
                    success=True,
                    message='Login successful',
                    login=login,
                    token=token
                )
            else:
                print("ERROR: Invalid password")
                return jsonify(success=False, message='Invalid login or password'), 401
        else:
            print("ERROR: User not found")
            return jsonify(success=False, message='Invalid login or password'), 401

    except Exception as e:
        print(f"ERROR: {e}")
        return jsonify(success=False, message='Internal server error'), 500
    finally:
        close_connection(connection, cursor)

@app.route('/user/all')
@app.route('/user/<int:user_id>')
def get_user(user_id=None):
    connection, cursor = get_connection()

    if user_id is None:
        cursor.execute('''SELECT login, password FROM USERS''')
        users_data = cursor.fetchall()
        connection.commit()
        close_connection(connection, cursor)

        return [User(i[0], i[1]).__dict__ for i in users_data]

    cursor.execute('''SELECT login, password FROM USERS WHERE user_order=%s''', [user_id])

    user_data = cursor.fetchall()

    connection.commit()
    close_connection(connection, cursor)

    if user_data.__len__() == 0:
        return abort(404, f"User with id {user_id} not found")

    return User(user_data[0][0], user_data[0][1]).__dict__


@app.route('/notes', methods=['GET'])
@token_required
def get_notes(current_user_id):
    user_id = request.args.get('userName')

    print("=== GET NOTES ENDPOINT CALLED ===")
    print(f"User ID from request: {user_id}")
    print(f"User ID from token: {current_user_id}")

    if not user_id:
        return jsonify(success=False, message='User ID is required'), 400

    # Проверяем, что пользователь запрашивает свои заметки
    if int(user_id) != current_user_id:
        return jsonify(success=False, message='Access denied'), 403

    connection, cursor = get_connection()
    try:
        cursor.execute('''SELECT notesid, notesdate, notestext, notesuserid 
                         FROM notes WHERE notesuserid = %s ORDER BY notesdate DESC''', (user_id,))
        notes_data = cursor.fetchall()

        print(f"Found {len(notes_data)} notes in database")

        notes = []
        for note in notes_data:

            note_dict = {
                'notesid': note[0],
                'notesdate': str(note[1]) if note[1] is not None else '',
                'notestext': note[2] if note[2] is not None else '',
                'noteuserid': note[3]
            }
            print(f"Note {note[0]}: date='{note_dict['notesdate']}', text='{note_dict['notestext']}'")
            notes.append(note_dict)

        return jsonify(success=True, notes=notes)

    except Exception as e:
        print(f"ERROR in get_notes: {e}")
        return jsonify(success=False, message='Internal server error'), 500
    finally:
        close_connection(connection, cursor)


@app.route('/user', methods=['GET'])
def get_user_by_id():
    user_id = request.args.get('id')

    if not user_id:
        return jsonify(success=False, message='User ID is required'), 400

    connection, cursor = get_connection()
    try:
        cursor.execute('''SELECT username, userpassword, userid 
                         FROM USERS WHERE userid = %s''', (user_id,))
        user_data = cursor.fetchone()

        if user_data:
            user = {
                'login': user_data[0],
                'password': user_data[1],
                'userid': user_data[2]
            }
            return jsonify(user)
        else:
            return jsonify(success=False, message='User not found'), 404

    except Exception as e:
        print(f"ERROR: {e}")
        return jsonify(success=False, message='Internal server error'), 500
    finally:
        close_connection(connection, cursor)


@app.route('/notes/create', methods=['POST'])
@token_required
def create_note(current_user_id):

    json = request.json

    if not request.is_json:
        return jsonify(success=False, message='Content-Type must be application/json'), 400

    if not json:
        return jsonify(success=False, message='No JSON data received'), 400

    if 'noteuserid' not in json:
        return jsonify(success=False, message='Missing required field: noteuserid'), 400

    if 'notestext' not in json:
        return jsonify(success=False, message='Missing required field: notestext'), 400

    user_id = json['noteuserid']
    note_text = json['notestext']

    if int(user_id) != current_user_id:
        return jsonify(success=False, message='Access denied'), 403

    json = request.json

    if not request.is_json:
        return jsonify(success=False, message='Content-Type must be application/json'), 400

    if not json:
        return jsonify(success=False, message='No JSON data received'), 400

    if 'noteuserid' not in json:
        return jsonify(success=False, message='Missing required field: noteuserid'), 400

    if 'notestext' not in json:
        return jsonify(success=False, message='Missing required field: notestext'), 400

    user_id = json['noteuserid']
    note_text = json['notestext']


    if user_id is None:
        return jsonify(success=False, message='User ID cannot be null'), 400

    if not isinstance(user_id, int):
        return jsonify(success=False, message='User ID must be integer'), 400

    if user_id <= 0:
        return jsonify(success=False, message='Invalid User ID'), 400

    if note_text is None:
        return jsonify(success=False, message='Note text cannot be null'), 400

    if not isinstance(note_text, str):
        return jsonify(success=False, message='Note text must be string'), 400

    note_text = note_text.strip()
    if not note_text:
        return jsonify(success=False, message='Note text cannot be empty'), 400

    if len(note_text) > 10000:  # или ваш лимит
        return jsonify(success=False, message='Note text too long'), 400

    connection, cursor = get_connection()
    try:
        cursor.execute('''SELECT userid FROM USERS WHERE userid = %s''', (user_id,))
        user_exists = cursor.fetchone()

        if not user_exists:
            return jsonify(success=False, message='User not found'), 404

        cursor.execute('''INSERT INTO notes (notestext, notesuserid) 
                         VALUES (%s, %s)''', (note_text, user_id))
        connection.commit()

        return jsonify(success=True, message='Note created successfully')

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify(success=False, message='Internal server error'), 500
    finally:
        close_connection(connection, cursor)


@app.route('/notes/delete', methods=['POST'])
@token_required
def delete_note(current_user_id):
    json = request.json

    if not request.is_json:
        return jsonify(success=False, message='Content-Type must be application/json'), 400

    if not json:
        return jsonify(success=False, message='No JSON data received'), 400

    if 'noteid' not in json:
        return jsonify(success=False, message='Missing required field: noteid'), 400

    note_id = json['noteid']

    connection, cursor = get_connection()
    try:
        cursor.execute('''SELECT notesid, notesuserid FROM notes WHERE notesid = %s''', (note_id,))
        note_exists = cursor.fetchone()

        if not note_exists:
            return jsonify(success=False, message='Note not found'), 404

        if note_exists[1] != current_user_id:
            return jsonify(success=False, message='Access denied'), 403

        cursor.execute('''DELETE FROM notes WHERE notesid = %s''', (note_id,))
        connection.commit()

        return jsonify(success=True, message='Note deleted successfully')

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify(success=False, message='Internal server error'), 500
    finally:
        close_connection(connection, cursor)

@app.route('/notes/update', methods=['POST'])
@token_required
def update_note(current_user_id):
    json = request.json

    if not request.is_json:
        return jsonify(success=False, message='Content-Type must be application/json'), 400

    if not json:
        return jsonify(success=False, message='No JSON data received'), 400

    if 'noteid' not in json or 'notestext' not in json:
        return jsonify(success=False, message='Missing required fields: noteid and notestext'), 400

    note_id = json['noteid']
    new_text = json['notestext']

    if not new_text or not new_text.strip():
        return jsonify(success=False, message='Note text cannot be empty'), 400

    new_text = new_text.strip()

    connection, cursor = get_connection()
    try:
        cursor.execute('''SELECT notesid, notesuserid FROM notes WHERE notesid = %s''', (note_id,))
        note_exists = cursor.fetchone()

        if not note_exists:
            return jsonify(success=False, message='Note not found'), 404

        if note_exists[1] != current_user_id:
            return jsonify(success=False, message='Access denied'), 403

        cursor.execute('''UPDATE notes SET notestext = %s WHERE notesid = %s''', (new_text, note_id))
        connection.commit()

        return jsonify(success=True, message='Note updated successfully')

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify(success=False, message='Internal server error'), 500
    finally:
        close_connection(connection, cursor)

if __name__ == '__main__':
    app.run(host=APP_HOST, port=APP_PORT, debug=True)