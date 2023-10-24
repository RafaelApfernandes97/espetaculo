from flask import Flask, render_template
import requests
import configparser
import re
import random
from flask import url_for
from flask import redirect
from flask import Flask, render_template, redirect, url_for, request, session, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from flask_pymongo import PyMongo
from pymongo import MongoClient, errors
from werkzeug.security import generate_password_hash
from werkzeug.security import check_password_hash
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Mail, Message
import string
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask import Flask, session, request, jsonify
import requests
from flask import request, jsonify
import mercadopago
from pydrive.auth import GoogleAuth
from pydrive.drive import GoogleDrive
from datetime import datetime
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi
import os
# DO pablo
from flask import Flask, redirect, request, session, url_for
from oauthlib.oauth2 import WebApplicationClient
import google.oauth2.credentials
import google_auth_oauthlib.flow
import googleapiclient.discovery
import os
import requests
from flask import request, jsonify
from flask_cors import CORS
from flask import Flask, request, jsonify, session, redirect, url_for
from pymongo import MongoClient, ReturnDocument
from pymongo.server_api import ServerApi
from flask_session import Session
from flask_socketio import SocketIO, emit


# ...

# Isso vai permitir requisições de qualquer origem. Em produção, você deve ser mais restritivo.


app = Flask(__name__)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")



gauth = GoogleAuth()

# Carrega client_secrets.json
gauth.LoadClientConfigFile("token.json")

# Cria o arquivo mycreds.txt após autenticação bem-sucedida
gauth.LoadCredentialsFile("mycreds.txt")

if gauth.credentials is None:
    # Autentica se ele não puder carregar nenhuma credencial válida
    gauth.LocalWebserverAuth()
elif gauth.access_token_expired:
    # Atualiza a credencial se ela estiver expirada
    gauth.Refresh()
else:
    gauth.Authorize()

# Verifica se a autenticação foi bem-sucedida
if gauth.credentials is not None:
    print("Autenticação concluída com sucesso!")

# Salva a credencial atual para o próximo run
gauth.SaveCredentialsFile("mycreds.txt")


# CONFIGURAÇÕES E KEY
bcrypt = Bcrypt(app)
config = configparser.ConfigParser()
config.read('config.ini')
users = {}
API_KEY = config['GoogleDrive']['API_KEY']
ID_PASTA_2023 = config['GoogleDrive']['FOLDER_ID_2023']
app.secret_key = 'AIzaSyDQo372qJ2'
mail = Mail(app)
app.config['SECRET_KEY'] = 'AIzaSyDQo372qJ22AIzaSyDQo372qJ2212'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'rafael.apfernandes78@gmail.com'
app.config['MAIL_PASSWORD'] = 'sjoaeeltujgndfio'
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['SESSION_TYPE'] = 'filesystem'
app.secret_key = 'some_secret_key'
# app.secret_key = 'AIzaSyDQo372qJ2pIycp2o5UQ69_G5Ut97kGlZM'

# CLIENT_ID = '860765167818-rmm48kgnh6lk5f288dsemnegpt4e7716.apps.googleusercontent.com'
# CLIENT_SECRET = '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'
# REDIRECT_URI = 'http://localhost:5000/oauth2callback'


# os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

app.secret_key = 'AIzaSyDQo372qJ2pIycp2o5UQ69_G5Ut97kGlZM'

CLIENT_ID = '860765167818-rmm48kgnh6lk5f288dsemnegpt4e7716.apps.googleusercontent.com'
CLIENT_SECRET = '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'


cli = WebApplicationClient(CLIENT_ID)


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
ACCESS_TOKEN = "TEST-2275512641158192-091820-f52d3de165f8c6c243f450a94b2f6472-730135180"
mp = mercadopago.SDK(ACCESS_TOKEN)


# BANCO DE DADOS
uri = "mongodb+srv://rafaelfernandes28031997:Rfernandes2112@cluster0.ftu7ytp.mongodb.net/?retryWrites=true&w=majority&appName=AtlasApp"
# Create a new client and connect to the server
client = MongoClient(uri, server_api=ServerApi('1'))
# Send a ping to confirm a successful connection

# Aqui, assumo que seu banco de dados é chamado 'mydatabase'. Substitua pelo nome correto.
db = client.mydatabase
try:
    client.admin.command('ping')
    print("Banco conectado com sucesso")
except Exception as e:
    print(e)


# ROTAS DE PAGINAS
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('list_events'))
    return redirect(url_for('login'))


@app.route('/reset')
def about():
    return render_template('reset_password.html')


@app.route('/forgot_password_form', methods=['GET'])
def forgot_password_form():
    return render_template('forgot_password_form.html')


# BUSCA A PASTA ANO
# LISTAGEM DOS EVENTOS
@app.route('/events')
def list_events():
    url = f"https://www.googleapis.com/drive/v3/files?q='{ID_PASTA_2023}'+in+parents&key={API_KEY}&orderBy=name&fields=files(id,name,mimeType,createdTime)"

    response = requests.get(url)
    all_folders = response.json().get('files', [])

    # Filtrar apenas pastas
    event_folders = [{
        "id": folder['id'],
        "name": folder['name'],
        "createdTime": datetime.strptime(folder['createdTime'], '%Y-%m-%dT%H:%M:%S.%fZ').strftime('%d/%m/%Y')
    } for folder in all_folders if folder['mimeType'] == 'application/vnd.google-apps.folder']

    return render_template('events.html', folders=event_folders)


# LISTAGEM DAS COREOGRAFIAS
def extract_number(s):
    num = ''.join(filter(str.isdigit, s))
    return int(num) if num else -1  # Retornando -1 se não houver número


@app.route('/event/<folder_id>')
def list_coreographies(folder_id):
    url = f"https://www.googleapis.com/drive/v3/files?q='{folder_id}'+in+parents&key={API_KEY}&fields=files(id,name,mimeType,createdTime)"
    response = requests.get(url)
    json_response = response.json()
    fotos_folder = next((folder for folder in json_response.get('files', []) if folder['mimeType']
                        == 'application/vnd.google-apps.folder' and folder['name'] == 'FOTOS'), None)

    if not fotos_folder:
        return "Pasta 'FOTOS' não encontrada", 404

    coreography_folders = []
    page_token = None

    while True:
        url_fotos = f"https://www.googleapis.com/drive/v3/files?q='{fotos_folder['id']}'+in+parents&key={API_KEY}&fields=files(id,name,mimeType,createdTime)"

        if page_token:
            url_fotos += f"&pageToken={page_token}"

        response_fotos = requests.get(url_fotos)
        json_response_fotos = response_fotos.json()
        coreography_folders.extend(json_response_fotos.get('files', []))

        page_token = json_response_fotos.get('nextPageToken', None)
        if not page_token:
            break
    print('folder_id')

    valid_coreography_folders = [folder for folder in coreography_folders if "coreografia" in folder['name'].lower(
    ) and extract_number(folder['name']) >= 0]

    # Ordenando as pastas filtradas
    sorted_coreography_folders = sorted(
        valid_coreography_folders, key=lambda x: extract_number(x['name']))

    return render_template('coreographies.html', folders=sorted_coreography_folders)


@app.route('/coreography/<folder_id>')
def show_images(folder_id):
    url = f"https://www.googleapis.com/drive/v3/files?q='{folder_id}'+in+parents&key={API_KEY}&orderBy=name&fields=files(id,name,mimeType,createdTime)"
    response = requests.get(url)
    all_files = response.json().get('files', [])

    # Filtrar arquivos .JPG
    jpg_files = [
        {
            "id": file['id'],
            "name": file['name'],
            "createdTime": formatDate(file.get('createdTime', 'Unknown')) if file.get('createdTime') else 'Unknown',
            "url": f"https://drive.google.com/uc?export=view&id={file['id']}"
        }
        for file in all_files if file['mimeType'].startswith('image/') and file['name'].endswith('.JPG')
    ]

    return render_template('images.html', files=jpg_files)


def formatDate(inputDate):
    from datetime import datetime

    date = datetime.fromisoformat(inputDate.replace('Z', '+00:00'))
    return date.strftime('%d/%m/%Y')


@app.route('/events')
def events():
    return render_template('events.html')


@app.route('/coreography/<folder_id>/random-image')
def get_random_image(folder_id):

    # Buscar todos os arquivos da pasta
    url = f"https://www.googleapis.com/drive/v3/files?q='{folder_id}'+in+parents&key={API_KEY}&orderBy=name"
    response = requests.get(url)
    all_files = response.json().get('files', [])

    # Filtrar arquivos .JPG
    jpg_files = [
        f"https://drive.google.com/uc?export=view&id={file['id']}"
        for file in all_files if file['mimeType'].startswith('image/') and file['name'].endswith('.JPG')
    ]

    # Selecionar uma imagem aleatória
    random_image_url = random.choice(jpg_files) if jpg_files else None

    if random_image_url:
        return redirect(random_image_url)
    else:
        return "No images found", 404


# LOGIN E REGISTRO
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


class User(UserMixin):
    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)

    def get_id(self):
        return self.id if hasattr(self, 'id') else None


@login_manager.user_loader
def user_loader(email):
    user_data = db.users.find_one({'email': email})
    if not user_data:
        return None

    return User(**user_data)


@app.route('/logout')
@login_required
def logout():
    # Remove o e-mail da sessão
    session.pop('email', None)

    logout_user()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = db.users.find_one({'email': email})

        # Verifica se o usuário foi encontrado no banco de dados
        if user:
            # Se a senha não estiver correta
            if not check_password_hash(user['password'], password):
                flash('Senha inválida', 'danger')
                return render_template('login.html')

            # Se a senha estiver correta
            # Se a verificação for bem-sucedida, adicione o e-mail à sessão
            session['email'] = email  # <-- Aqui está a linha importante

            # Se a verificação for bem-sucedida, crie um objeto de usuário e registre o login
            user_obj = User(**user)
            login_user(user_obj)

            if user.get('is_temp_password', False):
                return redirect(url_for('set_new_password'))

            flash('Logged in successfully!', 'success')
            return redirect(url_for('events'))

        else:
            flash('E-mail não encontrado', 'danger')
    return render_template('login.html')


@app.route('/set_new_password', methods=['GET', 'POST'])
def set_new_password():
    if request.method == 'POST':
        email = session.get('email')
        new_password = request.form['new_password']
        hashed_new_password = generate_password_hash(
            new_password, method='sha256')

        # Atualizando a senha no banco de dados e removendo o status de senha temporária
        db.users.update_one({'email': email}, {
                            '$set': {'password': hashed_new_password, 'is_temp_password': False}})

        flash('Password updated successfully!', 'success')
        return redirect(url_for('login'))

    return render_template('set_new_password.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        # Verificar se o e-mail já está registrado
        existing_user = db.users.find_one({"email": email})

        if existing_user:
            flash('O e-mail já está registrado!')
            return redirect(url_for('register'))

        hashed_pw = generate_password_hash(password)
        check_password_hash(hashed_pw, "senha_do_usuario")

        db.users.insert_one({"email": email, "password": hashed_pw})

        flash('Registro bem-sucedido! Por favor, faça login.')
        return redirect(url_for('login'))

    return render_template('register.html')


def generate_temp_password():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=10))


@app.route('/remove-from-cart', methods=['POST'])
def remove_from_cart():
    img_url = request.json.get('imgUrl')
    if 'cart' in session and img_url in session['cart']:
        session['cart'].remove(img_url)
        return jsonify(success=True), 200
    return jsonify(success=False, message="Image URL not found in session."), 400


@app.route('/forgot_password', methods=['POST'])
def forgot_password():
    email = request.form['email']

    # Verificando se o e-mail existe no banco de dados
    user = db.users.find_one({'email': email})

    if not user:
        flash('No account found with that e-mail.', 'danger')
        return redirect(url_for('forgot_password_form'))

    temp_password = generate_temp_password()
    hashed_password = generate_password_hash(temp_password, method='sha256')

    # Atualizando a senha temporária no banco de dados para este e-mail
    db.users.update_one({'email': email}, {
                        '$set': {'password': hashed_password, 'is_temp_password': True}})

    msg = Message('Password Reset Request',
                  sender='your_email@example.com', recipients=[email])
    msg.body = f'Your temporary password is: {temp_password}\nPlease use it to login and you will be prompted to reset it.'
    mail.send(msg)

    flash('E-mail sent with your temporary password!', 'success')
    return redirect(url_for('login'))


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = s.loads(token, salt='password-reset-salt', max_age=3600)
    except:
        return 'The reset link is invalid or has expired.'

    if request.method == 'POST':
        new_password = request.form['new_password']

        # Aqui, atualize a senha no banco de dados, lembre-se de criptografá-la antes de salvar

        return 'Password has been updated!'

    return render_template('reset_password.html')


# CARRINHO DE COMPRAS
@app.route('/save-cart', methods=['POST'])
def save_cart():
    data = request.get_json()
    cart = data.get('cart', [])

    # Aqui, armazene os detalhes do carrinho no banco de dados
    cart_data = {
        # assumindo que o email é usado como ID do usuário
        "user_id": session.get("email"),
        "items": cart,
        "date": datetime.utcnow()
    }
    db.cart_details.insert_one(cart_data)

    session['cart'] = cart
    return jsonify(status='success')


@app.route('/get-transactions', methods=['GET'])
def get_transactions():
    user_id = session.get("email")
    transactions = db.transactions.find({"user_id": user_id})
    return jsonify(transactions=list(transactions))


@app.route('/get-cart-details', methods=['GET'])
def get_cart_details():
    user_id = session.get("email")
    cart = db.cart_details.find_one({"user_id": user_id}, sort=[("date", -1)])
    return jsonify(cart=cart)


@app.route('/dashboard')
def dashboard_page():
    user_id = session.get("email")

    # Carregando transações
    transactions = list(db.transactions.find({"user_id": user_id}))

    # Carregando detalhes do carrinho
    cart_data = db.cart_details.find_one({"user_id": user_id}, sort=[
                                         ("date", -1)]) or {"items": []}
    cart_items = cart_data["items"]

    return render_template('dashboard.html', transactions=transactions, cart_items=cart_items)


# MERCADO PAGO


import requests

def create_payment_preference(items, payer):
    url = f"https://api.mercadopago.com/checkout/preferences?access_token={ACCESS_TOKEN}"
    preference = {
        "items": items,
        "payer": payer,
        "back_urls": {
            "success": "https://balletemfocoserver-dac43581212b.herokuapp.com/login2",
            "failure": "https://seu-site.com/pagamento-falha",
            "pending": "https://seu-site.com/pagamento-pendente"
        },
        "auto_return": "approved",
        "payment_methods": {
            "excluded_payment_methods": [
                {"id": "ticket"},
                {"id": "atm"},
            ],
            "installments": 12,
            "default_installments": 1,
        }
    }
    preference["payment_methods"]["installment_terms"] = [
        {
            "min_installments": 1,
            "max_installments": 3,
            "interest_rate": 0
        },
        {
            "min_installments": 4,
            "max_installments": 12,
        }
    ]

    response = requests.post(url, json=preference)

    if response.status_code == 201:
        return response.json()
    else:
        print(f"Erro ao criar preferência: {response.text}")
        return None



@app.route('/pending_payments')
@login_required
def show_pending_payments():
    user_id = current_user.get_id()
    payments = db.payments.find({'user_id': user_id})
    return render_template("payment_pending.html", payments=payments)


def get_payment_details(payment_id):
    headers = {
        "Authorization": f"Bearer {ACCESS_TOKEN}"
    }
    url = f"https://api.mercadopago.com/v1/payments/{payment_id}"
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        return response.json()
    else:
        return None
#

@app.route('/webhook', methods=['POST'])
def mercado_pago_webhook():
    data = request.get_json()

    if data.get('action') in ['payment.created', 'payment.updated']:
        payment_id = data['data']['id']

        # Armazenar payment_id na sessão
        session['payment_id'] = payment_id

        payment_response = mp.payment().get(payment_id)
        payment = payment_response["response"]

        payment_status = payment.get("status")

        if payment_status == "approved":
            print("Payment approved!")
            # Insira/Atualize no MongoDB
            db.payments.update_one({"payment_id": payment_id}, {"$set": {"status": "approved"}}, upsert=True)
            
            # Emita um evento WebSocket
            socketio.emit('payment_approved', {'payment_id': payment_id}, namespace='/payments')


    return jsonify(status='success'), 200

@app.route('/payment_status_page', methods=['GET'])
def payment_status_page():
    # Recuperar payment_id da sessão
    payment_id = session.get('payment_id', 'unknown')

    html_content = '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <title>Status do Pagamento</title>
    </head>
    <body>
        <h2>Status do Pagamento</h2>
        <p>ID do Pagamento: {}</p>
        <p>Status: {}</p>
    </body>
    </html>
    '''.format(payment_id, db.payments.find_one({"payment_id": payment_id})["status"])

    return html_content



#


@app.route('/create-mercado-pago-preference', methods=['POST'])
def create_mercado_pago_preference():
    data = request.json
    customer = data.get('customer', {})
    products = data.get('products', [])

    items = []
    for product in products:
        mp_item = {
            "title": product["title"],
            "quantity": 1,
            "currency_id": "BRL",
            "unit_price": product["price"]
        }
        items.append(mp_item)

    payer = {
        "name": customer["name"],
        "email": customer["email"],
        "phone": {
            "number": customer["phone"]
        }
    }

    preference_response = create_payment_preference(items, payer)

    if preference_response and "init_point" in preference_response:
        return jsonify(url=preference_response["init_point"])
    else:
        return jsonify(error="Erro ao criar o pagamento no Mercado Pago."), 400



REDIRECT_URI = 'https://balletemfocoserver-dac43581212b.herokuapp.com/oauth2callback'
@app.route('/index')
def index2():
    return 'Hello, World! <a href="/login2">Login with Google</a>'


@app.route('/login2')
def login_google_drive():
    google_provider_cfg = {
        "authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
        "token_endpoint": "https://oauth2.googleapis.com/token",
    }
    authorization_endpoint = google_provider_cfg["authorization_endpoint"]
    request_uri = cli.prepare_request_uri(
        authorization_endpoint,
        redirect_uri=REDIRECT_URI,
        scope=["https://www.googleapis.com/auth/drive"],
        prompt="consent",
    )
    return redirect(request_uri)


def move_files_to_folder(drive_service, file_ids, new_folder_id):
    for file_id in file_ids:
        # Fetch the existing parents to remove
        file = drive_service.files().get(fileId=file_id, fields='parents').execute()
        parents = file.get('parents')
        if parents:
            previous_parents = ",".join(parents)
        else:
            previous_parents = ""

        # Move the file to the new folder
        updated_file = drive_service.files().update(
            fileId=file_id,
            addParents=new_folder_id,
            removeParents=previous_parents,
            fields='id, parents'
        ).execute()


imgIDgoogle_server = []


@app.route('/store-img-ids', methods=['POST'])
def store_img_ids():
    global imgIDgoogle_server  # Indica que estamos trabalhando com a variável global

    # Verifique o conteúdo da requisição
    print("Dados recebidos:", request.json)

    # Tente obter os IDs de imagem com a chave 'imgIDs'
    img_ids = request.json.get('imgIDs', [])

    # Limpa a variável imgIDgoogle_server
    imgIDgoogle_server = []

    session['imgIDgoogle'] = img_ids
    # Verifique se o tipo é uma lista antes de estendê-lo
    if isinstance(img_ids, list):
        imgIDgoogle_server.extend(img_ids)
        print("imgIDgoogle_server atualizado:", session['imgIDgoogle'])
        return jsonify(success=True, message="IDs de imagem atualizados com sucesso.")
    else:
        print("Erro: os IDs de imagem não são uma lista.")
        return jsonify(success=False, message="Os IDs de imagem recebidos não são uma lista."), 400


@app.route('/oauth2callback')
def callback():
    # Log para visualizar a URL da requisição
    original_url = request.url
    print(f"Original request.url: {original_url}")

    # Substituir http por https
    https_url = original_url.replace("http://", "https://")
    print(f"Rewritten request.url: {https_url}")

    code = request.args.get("code")

    global imgIDgoogle_server

    google_provider_cfg = {
        "token_endpoint": "https://oauth2.googleapis.com/token",
    }
    token_endpoint = google_provider_cfg["token_endpoint"]

    token_url, headers, body = cli.prepare_token_request(
        token_endpoint,
        authorization_response=https_url,  # Use the rewritten https_url
        redirect_url=REDIRECT_URI,
        code=code
    )
    token_response = requests.post(
        token_url,
        headers=headers,
        data=body,
        auth=(CLIENT_ID, CLIENT_SECRET),
    )

    cli.parse_request_body_response(token_response.text)

    token_data = token_response.json()
    credentials = google.oauth2.credentials.Credentials(
        token=token_data.get('access_token'),
        refresh_token=token_data.get('refresh_token'),
        token_uri=token_data.get(
            'token_uri', 'https://oauth2.googleapis.com/token'),
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        # Correção aqui: alterando 'rapt_token' para 'id_token'
        id_token=token_data.get('id_token')
    )

    drive_service = googleapiclient.discovery.build(
        'drive', 'v3', credentials=credentials)

    folder_metadata = {
        'name': 'Compras Ballet Em Foco',
        'mimeType': 'application/vnd.google-apps.folder'
    }
    folder = drive_service.files().create(body=folder_metadata,
                                          fields='id').execute()

    # Adicionar esta parte para mover os arquivos
    file_ids = imgIDgoogle_server

    move_files_to_folder(drive_service, file_ids, folder.get('id'))

    return 'Folder ID: %s' % folder.get('id')



if __name__ == '__main__':
    # Use a porta definida pelo Heroku ou, se não estiver definida, 5000.
    port = int(os.environ.get('PORT', 5000))
    socketio.run(app)(host='0.0.0.0', port=port)
