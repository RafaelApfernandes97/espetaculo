from flask import Flask, render_template, request, session, jsonify
from auth import get_drive_service
from googleapiclient.errors import HttpError
from flask_httpauth import HTTPBasicAuth
import mercadopago

import re

app = Flask(__name__)

drive_service = get_drive_service()


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
            q=f"'{folder_id}' in parents and mimeType='application/vnd.google-apps.folder'",
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
        q=f"name='{name}' and '{parent_id}' in parents and mimeType='application/vnd.google-apps.folder'",
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

    phone_number = request.form.get('phone_number')  # Captura o número de telefone
    if not phone_number:
        return "Número de telefone não fornecido."

    selected_images = request.form.getlist('selected_images')  # IDs das imagens selecionadas
    new_folder_id = create_new_folder(phone_number, drive_service)  # Usa o número de telefone como nome da pasta
    set_folder_permissions(new_folder_id, drive_service)  # Configura a permissão
    
    for image_id in selected_images:
        copy_file_to_folder(image_id, new_folder_id, drive_service)
    
    folder_link = f"https://drive.google.com/drive/folders/{new_folder_id}"
    
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
