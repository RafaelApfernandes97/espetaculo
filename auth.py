from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from google.oauth2.service_account import Credentials

def get_drive_service():
    creds = None
    try:
        # Carregue as credenciais da conta de serviço
        creds = Credentials.from_service_account_file('ballet-em-foco-0a453c63c5b1.json',
                                                      scopes=['https://www.googleapis.com/auth/drive'])
        
        drive_service = build('drive', 'v3', credentials=creds)
        
        # Tentativa de listagem simples para verificar a autenticação
        results = drive_service.files().list(pageSize=10).execute()
        
        # Se chegarmos até aqui, a autenticação foi bem-sucedida
        print("Autenticação com Google Drive bem-sucedida!")
        return drive_service

    except HttpError as e:
        print(f"Erro ao autenticar com Google Drive: {e}")
        return None

    except Exception as e:
        print(f"Erro desconhecido: {e}")
        return None
