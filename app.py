from flask import Flask, render_template, request, session, jsonify, redirect
from auth import get_drive_service
from googleapiclient.errors import HttpError
from flask_httpauth import HTTPBasicAuth
import mercadopago
from pymongo import MongoClient, server_api
from flask_cors import CORS
from flask_cors import cross_origin
from flask_mail import Mail, Message
from bson import ObjectId

import re

app = Flask(__name__)
CORS(app)

app.config['MAIL_SERVER'] = 'smtp.googlemail.com'  # por exemplo, para o Gmail
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'rafael.apfernandes78@gmail.com'
app.config['MAIL_PASSWORD'] = 'zaqhhazrejjtqyto'

mail = Mail(app)


# BANCO DE DADOS
uri = "mongodb+srv://rafaelfernandes28031997:Rfernandes2112@cluster0.ftu7ytp.mongodb.net/?retryWrites=true&w=majority&appName=AtlasApp"
# Create a new client and connect to the server
client = MongoClient(uri, server_api=server_api.ServerApi('1'))
# Send a ping to confirm a successful connection

# Aqui, assumo que seu banco de dados é chamado 'mydatabase'. Substitua pelo nome correto.
db = client.mydatabase
try:
    client.admin.command('ping')
    print("Banco conectado com sucesso")
except Exception as e:
    print(e)


drive_service = get_drive_service()


ACCESS_TOKEN = 'APP_USR-2275512641158192-091820-0ddcaf387fd3db012d7cd5446837b56f-730135180'
sdk = mercadopago.SDK(ACCESS_TOKEN)


@app.route('/purchase_images', methods=['POST'])
@cross_origin()
def purchase_images():
    selected_images = request.form.getlist('selected_images')

    if not selected_images:
        return "Nenhuma imagem selecionada."

    image_price = 1

    preference_data = {
        "items": [
            {
                "title": "Compra de imagens",
                "quantity": len(selected_images),
                "currency_id": "BRL",
                "unit_price": image_price
            }
        ],
        "back_urls": {
            "success": request.url_root + "payment_success",
            "failure": request.url_root + "payment_failure",
            "pending": request.url_root + "payment_pending"
        },
        "auto_return": "approved"  # Adicionado para redirecionamento automático
    }

    preference_response = sdk.preference().create(preference_data)
    preference = preference_response["response"]

    # Armazenar phone_number, email_address e selected_images no banco de dados usando preference_id como chave
    temp_data = {
        "_id": preference['id'],  # Usando preference_id como chave
        "phone_number": request.form.get('phone_number'),
        "email_address": request.form.get('email_address'),  # Adicionado
        "selected_images": selected_images
    }

    try:
        db.temp_payment_data.insert_one(temp_data)
    except errors.DuplicateKeyError:
        # Se já existir um registro com esse _id, apenas atualize o registro existente
        db.temp_payment_data.update_one(
            {"_id": preference['id']}, {"$set": temp_data})

    if 'init_point' in preference:
        # Se a preferência foi criada com sucesso, envie um e-mail de confirmação
        msg = Message('Finalizar Pagamento - Ballet em Foco',
                      sender='rafael.apfernandes78@gmail.com', recipients=[temp_data['email_address']])
        msg.body = "Obrigado pela sua compra! \n Para finalizar o seu pedido, clique no link para finalizar o pagamento: {} \n Caso ja tenha realizado o pagamento desconsidere esse e-mail.".format(
            preference['init_point'])
        mail.send(msg)

        return jsonify({"redirect_url": preference['init_point']})
    else:
        return "Erro ao criar preferência de pagamento."


def send_drive_link_to_email(email_address, folder_link):
    msg = Message('Compra Finalizada - Ballet em Foco',
                  sender='rafael.apfernandes78@gmail.com', recipients=[email_address])
    msg.body = f"Obrigado pela sua compra!\n Aqui está o link para acessar suas imagens: \n {
        folder_link}"
    mail.send(msg)


@app.route('/payment_success', methods=['GET'])
def payment_success():
    payment_id = request.args.get('payment_id')
    preference_id = request.args.get('preference_id')
    status = request.args.get('status')
    print("Payment ID:", payment_id)
    print("Status:", status)

    if not payment_id or status != 'approved':
        return jsonify({"error": "Payment ID not provided or payment not approved."}), 400

    payment_info = sdk.payment().get(payment_id)
    print(payment_info)

    if payment_info['response'].get('status') == 'approved':
        # Recuperar phone_number, email_address e selected_images do banco de dados
        temp_data = db.temp_payment_data.find_one({"_id": preference_id})
        
        if not temp_data:
            return jsonify({"error": "Dados temporários não encontrados."}), 400

        phone_number = temp_data["phone_number"]
        email_address = temp_data["email_address"]
        selected_images = temp_data["selected_images"]

        # Aqui, você pode decidir se deseja deletar os dados temporários após o uso
        db.temp_payment_data.delete_one({"_id": preference_id})

        folder_link_response = copy_selected_images_to_drive(phone_number, selected_images)

        # Obter o link real da pasta do response
        start_link_index = folder_link_response.find("https://drive.google.com/")
        end_link_index = folder_link_response.find("'>Clique aqui")
        folder_link = folder_link_response[start_link_index:end_link_index]

        # Enviar o link da pasta para o e-mail do cliente
        send_drive_link_to_email(email_address, folder_link)

        # Prepare the data to be inserted into the database
        payment_info['response']['_id'] = ObjectId()  # Gerar um novo _id
        payment_info['response']['drive_folder_link'] = folder_link
        # Insert the data into the database
        print (folder_link)
        db.payments_history.insert_one(payment_info['response'])

        return folder_link_response

    return jsonify({"error": "Payment not approved."}), 400


@app.route('/payment_failure')
def payment_failure():
    return "Pagamento falhou."


@app.route('/payment_pending')
def payment_pending():
    return "Pagamento pendente."


def copy_selected_images_to_drive(phone_number, selected_images):
    drive_service = get_drive_service()
    if not drive_service:
        return "Erro ao autenticar com o Google Drive."

    if not phone_number:
        return "Número de telefone não fornecido."

    new_folder_id = create_new_folder(phone_number, drive_service)
    set_folder_permissions(new_folder_id, drive_service)

    for image_id in selected_images:
        copy_file_to_folder(image_id, new_folder_id, drive_service)

    folder_link = f"https://drive.google.com/drive/folders/{new_folder_id}"
    return f"Imagens copiadas com sucesso! <a href='{folder_link}'>Clique aqui para acessar a pasta</a>"


@app.route('/payments_history', methods=['GET'])
def payments_history():
    payments = list(db.payments_history.find())
    return render_template('payments_history.html', payments=payments)


# Rota 1: Lista os eventos (pastas) dentro da pasta "2023".
@app.route('/')
def index():
    try:
        folder_id = find_folder_id_by_name('2023')
        events = list_folders_inside_folder(folder_id)
        return render_template('index.html', events=events)
    except HttpError as error:
        return f"An error occurred: {error}"


def find_folder_id_by_name(name):
    response = drive_service.files().list(
        q=f"name='{name}' and mimeType='application/vnd.google-apps.folder'",
        spaces='drive',
        fields='files(id, name)').execute()
    folders = response.get('files', [])
    return folders[0]['id'] if folders else None


def list_folders_inside_folder(folder_id):
    results = []
    page_token = None
    while True:
        response = drive_service.files().list(
            q=f"'{
                folder_id}' in parents and mimeType='application/vnd.google-apps.folder'",
            spaces='drive',
            fields='nextPageToken, files(id, name)',
            pageToken=page_token,
            orderBy="name"  # Isso irá ordenar os resultados pelo nome
        ).execute()

        items = response.get('files', [])
        results.extend(items)

        # Verifica se há mais páginas para buscar
        page_token = response.get('nextPageToken', None)
        if page_token is None:
            break

    # Reordenando os resultados baseados no número extraído do nome da coreografia
    def folder_sort_key(item):
        match = re.search(r'(\d+)', item['name'])
        # Se a expressão regular encontrar um número, ela retornará esse número.
        # Caso contrário, ela retornará 0 para garantir que o item seja colocado no início da lista.
        return int(match.group(1)) if match else 0

    results = sorted(results, key=folder_sort_key)

    return results


# Rota 2: Lista as pastas de fotos dentro da pasta "Fotos" de um evento específico.
@app.route('/event/<event_id>')
def show_event_folders(event_id):
    try:
        fotos_folder_id = find_folder_id_by_name_and_parent('Fotos', event_id)
        photo_folders = list_folders_inside_folder(fotos_folder_id)
        return render_template('event_folders.html', folders=photo_folders, event_id=event_id)

    except Exception as e:
        # Imprimindo a exceção para o terminal
        print("Erro ao processar a pasta do evento:", str(e))
        print("Event ID:", event_id)

        return f"An error occurred: {str(e)}"


def find_folder_id_by_name_and_parent(name, parent_id):
    response = drive_service.files().list(
        q=f"name='{name}' and '{
            parent_id}' in parents and mimeType='application/vnd.google-apps.folder'",
        spaces='drive',
        fields='files(id, name)').execute()
    folders = response.get('files', [])
    return folders[0]['id'] if folders else None

# Rota 3: Lista e visualiza as imagens dentro de uma pasta de fotos específica.


@app.route('/event/<event_id>/folder/<folder_id>')
def show_photos(event_id, folder_id):
    try:
        images = list_images_in_folder(folder_id)
        return render_template('event_photos.html', images=images, event_id=event_id)

    except HttpError as error:
        return f"An error occurred: {error}"


def list_images_in_folder(folder_id):
    response = drive_service.files().list(
        q=f"'{folder_id}' in parents and mimeType='image/jpeg'",
        spaces='drive',
        fields='files(id, name)').execute()
    return response.get('files', [])


# Rota 4: Seleciona e copia as imagens para a pasta do google drive

@app.route('/copy_selected_images', methods=['POST'])
def copy_selected_images():
    drive_service = get_drive_service()  # Obtenha o serviço
    if not drive_service:
        return "Erro ao autenticar com o Google Drive."

    # Captura o número de telefone
    phone_number = request.form.get('phone_number')
    if not phone_number:
        return "Número de telefone não fornecido."

    selected_images = request.form.getlist(
        'selected_images')  # IDs das imagens selecionadas
    # Usa o número de telefone como nome da pasta
    new_folder_id = create_new_folder(phone_number, drive_service)
    # Configura a permissão
    set_folder_permissions(new_folder_id, drive_service)

    for image_id in selected_images:
        copy_file_to_folder(image_id, new_folder_id, drive_service)

    folder_link = f"https: //drive.google.com/drive/folders/{new_folder_id}"

    return f"Imagens copiadas com sucesso! <a href='{folder_link}'>Clique aqui para acessar a pasta</a>"


def set_folder_permissions(folder_id, drive_service):
    """Dá permissão de leitura para qualquer pessoa com o link da pasta."""
    permission = {
        'type': 'anyone',
        'role': 'reader',
    }
    drive_service.permissions().create(fileId=folder_id, body=permission).execute()


def create_new_folder(folder_name, drive_service):
    file_metadata = {
        'name': folder_name,
        'mimeType': 'application/vnd.google-apps.folder'
    }
    folder = drive_service.files().create(body=file_metadata, fields='id').execute()
    return folder.get('id')


def copy_file_to_folder(file_id, folder_id, drive_service):
    copied_file = {'parents': [folder_id]}
    drive_service.files().copy(fileId=file_id, body=copied_file).execute()


if __name__ == '__main__':
    app.run(debug=True)
