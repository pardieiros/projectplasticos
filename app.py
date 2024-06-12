import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from flask import Flask, render_template, redirect, url_for, request, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from pymongo import MongoClient
import os
from flask import g
import sqlite3
from flask import Flask, request
from bs4 import BeautifulSoup
import requests
from flask_excel import make_response_from_array
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from flask import render_template, get_flashed_messages
from flask import render_template, request, redirect, url_for, flash
from flask import Flask, render_template, request, redirect, url_for, flash, session


# Configurações do servidor SMTP
SMTP_SERVER = 'mail.plasticosdao.com'
SMTP_PORT = 587
SMTP_USERNAME = 'marco@plasticosdao.com'
SMTP_PASSWORD = 'calbanom'



def send_email(to_email, subject, body, is_html=True):
    msg = MIMEMultipart()
    msg['From'] = SMTP_USERNAME
    msg['To'] = to_email
    msg['Subject'] = subject

    print("user, email, subject", SMTP_USERNAME, to_email, subject)

    mime_type = 'html' if is_html else 'plain'
    msg.attach(MIMEText(body, mime_type))

    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.starttls()
        server.login(SMTP_USERNAME, SMTP_PASSWORD)
        server.send_message(msg)




uri = "mongodb+srv://marco:Xpto001%3F@atlascluster.oomtbkh.mongodb.net/"
app = Flask(__name__, static_folder='static')  # Defina o diretório de arquivos estáticos
app.secret_key = secret_key = os.urandom(24)  # Gera uma chave secreta de 24 bytes.

username=0

# Criar um cliente MongoDB
client = MongoClient(uri)

# Selecionar a base de dados (será criada se não existir)
dbmongo = client['Logins']

# Selecionar a coleção (será criada se não existir)
collection = dbmongo['users']


@app.route('/update-order', methods=['POST'])
def update_order():
    numero_encomenda = request.form.get('numero_encomenda')
    numero_dossier = request.form.get('numero_dossier')
    print("helloworld")
    try:
        # Atualizar banco de dados SQLite
        db = get_encomendas_db()
        cursor = db.cursor()
        
        print("Conectado ao banco de dados SQLite")

        # Obter encomenda_id com base no numero_encomenda
        cursor.execute('SELECT id, cliente_id FROM Encomendas WHERE numero = ?', (numero_encomenda,))
        encomenda = cursor.fetchone()
        print(f"Resultado da consulta ao banco de dados: {encomenda}")
        
        if not encomenda:
            print("Encomenda não encontrada")
            return jsonify({'success': False, 'message': 'Encomenda não encontrada'})

        encomenda_id, cliente_id = encomenda[0], encomenda[1]
        print(f"Encomenda encontrada: id={encomenda_id}, cliente_id={cliente_id}")

        # Atualizar ItensEncomenda
        cursor.execute('UPDATE ItensEncomenda SET numero_dossier = ?, status = ? WHERE encomenda_id = ?', 
                       (numero_dossier, 'Enviado', encomenda_id))
        db.commit()
        print("ItensEncomenda atualizado")

        # Obter email do cliente do MongoDB
        print(f"Buscando cliente no MongoDB com username={cliente_id}")
        cliente = collection.find_one({"username": cliente_id})
        if not cliente:
            print("Cliente não encontrado no MongoDB")
            return jsonify({'success': False, 'message': 'Cliente não encontrado'})

        email_cliente = cliente['email']
        print(f"Email do cliente: {email_cliente}")

        # Enviar email ao cliente
        subject = 'Encomenda Pronta para Envio'
        body = f'A sua encomenda {numero_encomenda}, está pronta e segue para envio.'
        send_email(email_cliente, subject, body)
        print("Email enviado")

        flash('Alterações guardadas com sucesso')

        return jsonify({'success': True})

    except Exception as e:
        print(f"Erro: {str(e)}")
        return jsonify({'success': False, 'message': str(e)})

    finally:
        db.close()
        print("Conexão com o banco de dados SQLite fechada")

@app.route('/api/encomendasall', methods=['GET'])
def get_all_encomendas():
    try:
        # Verificar se o usuário está logado
        if 'username' not in session:
            return jsonify({"error": "Usuário não logado"}), 401
        
        # Consultar o banco de dados SQLite para obter todas as encomendas
        db = get_encomendas_db()
        cursor = db.cursor()
        cursor.execute("""
            SELECT E.numero, E.data, E.cliente_id, IFNULL(IE.status, 'Sem Status'), IFNULL(IE.numero_dossier, 'Sem Dossier')
            FROM Encomendas E
            LEFT JOIN ItensEncomenda IE ON E.id = IE.encomenda_id
            GROUP BY E.id
        """)
        encomendas = cursor.fetchall()

        return jsonify({"encomendas": encomendas}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/encomendas/<numero>', methods=['GET'])
def get_encomenda(numero):
    try:
        db = get_encomendas_db()
        cursor = db.cursor()
        
        # Consulta para obter os detalhes da encomenda
        cursor.execute("""
            SELECT id, numero, data, cliente_id
            FROM Encomendas
            WHERE numero = ?
        """, (numero,))
        encomenda = cursor.fetchone()
        
        if not encomenda:
            return jsonify({"error": "Encomenda não encontrada"}), 404

        encomenda_id = encomenda[0]  # ID da encomenda
        
        # Consulta para obter os itens da encomenda
        cursor.execute("""
            SELECT tipo, tamanho, cor, quantidade, numero_caixa, quantidade_por_caixa, status
            FROM ItensEncomenda
            WHERE encomenda_id = ?
        """, (encomenda_id,))
        items = cursor.fetchall()
        
        # Fechar a conexão com o banco de dados
        db.close()
        
        return jsonify({
            "encomenda": {
                "numero": encomenda[1],
                "data": encomenda[2],
                "cliente_id": encomenda[3],
                "items": items
            }
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
@app.route('/api/encomendas', methods=['GET'])
def get_encomendas():
    try:
        # Verificar se o usuário está logado
        if 'username' not in session:
            return jsonify({"error": "Usuário não logado"}), 401
        
        # Recuperar o nome de usuário do usuário logado
        username = session['username']
        print("usermongo", username)
        
        # Consultar o banco de dados MongoDB para obter o usuário pelo nome de usuário
        user = collection.find_one({"username": username})
        if not user:
            return jsonify({"error": "Usuário não encontrado"}), 404
        
        # Obter o ID do usuário convertido para um tipo de dados suportado pelo SQLite
        user_id = str(user['username'])
        
        print("user", user_id)
        
        # Consultar o banco de dados SQLite para obter as encomendas do usuário logado
        db = get_encomendas_db()
        cursor = db.cursor()
        cursor.execute("""
            SELECT E.numero, E.data, E.cliente_id, IFNULL(IE.status, 'Sem Status')
            FROM Encomendas E
            LEFT JOIN ItensEncomenda IE ON E.id = IE.encomenda_id
            WHERE E.cliente_id = ?
            GROUP BY E.id
        """, (user_id,))
        encomendas = cursor.fetchall()

        print("encomendas", encomendas)

        return jsonify({"encomendas": encomendas}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500




@app.route('/get_user_iframe', methods=['GET'])
def get_user_iframe():
    try:
        # Verificar se o usuário está logado
        if 'logged_in' not in session or not session['logged_in']:
            return jsonify({"error": "Usuário não está logado"})

        # Buscar o URL do iframe para o usuário atual na base de dados
        username = session['username']
        user = collection.find_one({"username": username})
        iframe_url = user.get('iframe_url', '')

        return jsonify({"iframeUrl": iframe_url})
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route('/update_user_iframe', methods=['POST'])
def update_user_iframe():
    username = request.json.get('username')
    iframe_url = request.json.get('iframeUrl')

    try:
        collection.update_one({"username": username}, {"$set": {"iframe_url": iframe_url}})
        return jsonify({"status": "success"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route('/usersiframe', methods=['GET'])
def get_usersiframe():
    users = list(collection.find({}, {"_id": 0, "username": 1, "email": 1, "isAdmin": 1, "access_paletes": 1, "access_ferramenta_preco": 1, "iframe_url": 1}))
    return jsonify(users)


@app.route('/users', methods=['GET'])
def get_users():
    users = list(collection.find({}, {"_id": 0, "username": 1, "email": 1, "isAdmin": 1, "access_paletes": 1, "access_ferramenta_preco": 1, "access_encomendas": 1, "access_encomendasgerir": 1}))
    return jsonify(users)

@app.route('/update_user_permissions', methods=['POST'])
def update_user_permissions():
    updates = request.json.get('updates', [])
    for update in updates:
        collection.update_one({"username": update['username']}, {
            "$set": {
                "isAdmin": update['isAdmin'],
                "access_paletes": update['access_paletes'],
                "access_ferramenta_preco": update['access_ferramenta_preco'],
                "access_encomendas": update['access_encomendas'],
                "access_encomendasgerir": update['access_encomendasgerir']
            }
        })
    return jsonify({"status": "success"})

@app.route('/get_stock', methods=['POST'])
def get_stock():
    # Obtenha o código do artigo da solicitação JSON
    data = request.get_json()
    artigo = data.get('artigo')

    if not artigo:
        return jsonify({'error': 'Código de artigo não fornecido'}), 400

    # URL da página web com estoque
    url = "http://plasticosdao.ddns.net/Portal/programs/genform.aspx?codigo=STOCKS&tmp_usr=Testeb&tmp_psw=testeb"

    try:
        # Faça uma solicitação GET para a página web
        response = requests.get(url)
        if response.status_code == 200:
            html = response.content

            # Use BeautifulSoup para analisar o HTML e extrair as informações de estoque da tabela
            stock_data = extract_stock_from_html(html, artigo)

            return jsonify({'stock_data': stock_data})
        else:
            return jsonify({'error': 'Falha ao obter página web'}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def extract_stock_from_html(html, artigo):
    soup = BeautifulSoup(html, 'html.parser')
    stock_table = soup.find('table', class_='table')  # Assumindo que a tabela desejada é a primeira tabela com a classe 'table'
    rows = stock_table.find_all('tr', class_='tabeladocstd')

    print("Artigo a ver:", artigo)

    for row in rows:
        columns = row.find_all('td')
        
        # Ignora linhas de subtítulo
        if len(columns) == 1:
            continue

        referencia = columns[0].text.strip()
        
        # Adicionar informações de depuração
        print(f"Comparando '{referencia}' com '{artigo}'")
        if referencia == artigo:
            designacao = columns[1].text.strip()
            stock = columns[2].text.strip()
            print(f"Artigo encontrado: {referencia}, {designacao}, {stock}")
            return {'referencia': referencia, 'designacao': designacao, 'stock': stock}
    
    return {'error': 'Artigo não encontrado no estoque'}

@app.route('/api/save-encomenda', methods=['POST'])
def save_encomenda():
    data = request.get_json()
    encomenda = data.get('encomenda')

    if not encomenda:
        return jsonify({"error": "Dados da encomenda não fornecidos"}), 400

    try:
        db = get_encomendas_db()
        cursor = db.cursor()
        cursor.execute("""
            INSERT INTO Encomendas (numero, data, cliente_id)
            VALUES (?, ?, ?)
        """, (encomenda['numero'], encomenda['data'], encomenda['cliente_id']))
        encomenda_id = cursor.lastrowid
        db.commit()

        return jsonify({"message": "Encomenda salva com sucesso", "encomenda_id": encomenda_id}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/save-itens-encomenda', methods=['POST'])
def save_itens_encomenda():
    data = request.get_json()
    items = data.get('items')

    if not items:
        return jsonify({"error": "Itens da encomenda não fornecidos"}), 400

    try:
        db = get_encomendas_db()
        cursor = db.cursor()
        
        # Iniciar uma transação
        db.execute('BEGIN')
        
        for item in items:
            cursor.execute("""
                INSERT INTO ItensEncomenda (encomenda_id, tipo, tamanho, cor, quantidade, numero_caixa, quantidade_por_caixa, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, 'Em Produção')
            """, (item['encomenda_id'], item['tipo'], item['tamanho'], item['cor'], item['quantidade'], item['numero_caixa'], item['quantidade_por_caixa']))
        
        db.commit()

        return jsonify({"message": "Itens da encomenda salvos com sucesso"}), 201
    except Exception as e:
        db.rollback()
        return jsonify({"error": str(e)}), 500
    

@app.route('/convert_table', methods=['POST'])
def convert_table():
    table_html = request.json.get('table_html')

    if not table_html:
        return jsonify({"error": "Table HTML is required"}), 400

    try:
        # Parse do HTML da tabela usando BeautifulSoup
        soup = BeautifulSoup(table_html, 'html.parser')

        # Encontrar a tabela no HTML
        table = soup.find('table', id='tabela_dados')

        if not table:
            return jsonify({"error": "Table with id 'tabela_dados' not found"}), 404

        # Extract table text
        table_text = []

        # Capture header
        header = table.find('thead')
        if header:
            header_row = [cell.get_text(strip=True) for cell in header.find_all('th')]
            table_text.append(header_row)

        # Capture body rows
        body = table.find('tbody')
        if body:
            for row in body.find_all('tr'):
                cells = [cell.get_text(strip=True) for cell in row.find_all('td')]
                table_text.append(cells)
        else:
            # If tbody is not present, fall back to direct tr children of table
            for row in table.find_all('tr'):
                cells = [cell.get_text(strip=True) for cell in row.find_all(['td', 'th'])]
                table_text.append(cells)

        return jsonify({"table_text": table_text}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

def send_email_with_attachment(to_email, subject, body, attachment_data):
    msg = MIMEMultipart()
    msg['From'] = SMTP_USERNAME
    msg['To'] = to_email
    msg['Subject'] = subject

    print("user, email, subject", SMTP_USERNAME, to_email, subject)

    # Attach body
    msg.attach(MIMEText(body, 'plain'))

    # Attach attachment
    attachment = MIMEBase('application', 'octet-stream')
    attachment.set_payload(attachment_data)
    encoders.encode_base64(attachment)
    attachment.add_header('Content-Disposition', 'attachment', filename='dados.xlsx')
    msg.attach(attachment)

    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.starttls()
        server.login(SMTP_USERNAME, SMTP_PASSWORD)
        server.send_message(msg)

@app.route('/send_email_with_attachment', methods=['POST'])
def send_email_with_attachment_route():
    data = request.files['file']
    to_email = request.form['to']
    subject = request.form['subject']
    body = request.form['body']


    app.logger.debug(f"Received file: {data.filename}")
    app.logger.debug(f"To email: {to_email}")
    app.logger.debug(f"Subject: {subject}")
    app.logger.debug(f"Body: {body}")
    
    attachment_data = data.read()
    
    try:
        send_email_with_attachment(to_email, subject, body, attachment_data)
        return jsonify({"success": True, "message": "E-mail sent successfully!"}), 200
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@app.route('/register', methods=['POST'])
def register():
    nome = request.form.get('nameregist')
    email = request.form.get('emailregist')
    username = request.form.get('userregist')
    password = request.form.get('passwordregist')
    client_type = request.form.get('client_type')

    if not all([nome, email, username, password, client_type]):
        flash('Por favor, preencha todos os campos!')
        return redirect(url_for('home'))

    # Verifica se o usuário já existe
    existing_user = collection.find_one({"username": username})
    if existing_user:
        flash('Username já está em uso!')
        return redirect(url_for('home'))

    # Hash da senha
    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

    # Cria um novo usuário
    new_user = {
        "nome": nome,
        "email": email,
        "username": username,
        "password": hashed_password,
        "client_type": client_type
    }


    # Insere o novo usuário na coleção
    collection.insert_one(new_user)

    # Enviar e-mail com credenciais
    subject = "Bem-vindo às ferramentas da Plasticos Dão"
    body = f"""Olá {nome},
    
    Obrigado por se registrar. Abaixo estão suas credenciais:
    
    Username: {username}
    Email: {email}
    Password: {password}
    
    ***Esta é uma senha não criptografada. Recomendamos que você altere sua senha assim que possível.***

    Estamos a testar uma nova ferramenta para Revendedores.
    Esta ferramenta vai permitir que os Revendedores encomendem paletes personalizadas com vários formatos de sacos, de forma mais eficiente, ocupando todo o espaço disponível da palete.
    Pode efectuar no seguinte link:
    http://pardieirosmedia.ddns.net/
    Ainda estamos numa fase embrionária, mas já é possível consegue criar paletes personalizadas e pedir-nos as encomendas.

    
    
    Atenciosamente,
    A equipa de Ferramentas - Plasticos Dão
    Marco Tavares"""
    send_email(email, subject, body, is_html=False)

    flash('Registrado com sucesso! Agora você pode fazer login.')
    return redirect(url_for('home'))

@app.route('/gerar_excel')
def gerar_excel():
    # Dados da tabela
    dados = [
        ["Artigo", "Designação", "Quantidade"],
        ["ATB24113290", "", "6000"],
        ["", "Palete 2", ""],
        ["ATB24113290", "", "250"]
    ]

    # Crie um buffer de memória para armazenar o arquivo Excel
    output = io.BytesIO()

    # Use a função make_response_from_array para criar a resposta do Flask a partir dos dados
    response = make_response_from_array(dados, 'xlsx', file_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', file_name='dados_excel')

    # Envie o arquivo Excel
    return response

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('userlogin')
    password = request.form.get('passwordlogin')

    user = collection.find_one({"username": username})

    if user and check_password_hash(user['password'], password):
        session['logged_in'] = True
        session['username'] = username
        session['isAdmin'] = user.get('isAdmin', False)
        session['access_paletes'] = user.get('access_paletes', False)
        session['access_ferramenta_preco'] = user.get('access_ferramenta_preco', False)
        session['access_encomendas'] = user.get('access_encomendas', False)
        flash('Login bem-sucedido!', 'success')
    else:
        flash('Credenciais inválidas!', 'error')

    return redirect(url_for('home'))

@app.route('/settings', methods=['GET'])
def settings():
    if 'username' not in session:
        flash('Você precisa estar logado para acessar esta página.')
        return redirect(url_for('home'))

    username = session['username']
    user = collection.find_one({"username": username})

    if not user:
        flash('Usuário não encontrado.')
        return redirect(url_for('home'))

    # Print the user value to debug
    print("Valor do usuário:", user)
    
    return render_template('accountsettings.html', user=user)


@app.route('/update_settings', methods=['POST'])
def update_settings():
    if 'username' not in session:
        flash('Você precisa estar logado para acessar esta página.')
        return redirect(url_for('home'))

    username = session['username']
    user = collection.find_one({"username": username})

    if not user:
        flash('Usuário não encontrado.')
        return redirect(url_for('home'))

    # Verificar se o tipo de cliente é "empresarial" e salvar o nome da empresa
    client_type = request.form.get('client_type')
    updated_data = {
        "email": request.form.get('email'),
        "client_type": client_type,
        "moradac": request.form.get('moradac'),
        "morada": request.form.get('morada'),
        "nif": request.form.get('nif'),
        "country": request.form.get('country'),
        "indicative": request.form.get('indicative'),
        "numberphone": request.form.get('numberphone')
    }

    if client_type == "empresarial":
        updated_data["nome_empresa"] = request.form.get('nome_empresa')

    # Atualize apenas os campos que foram fornecidos
    collection.update_one({"username": username}, {"$set": updated_data})

    flash('Configurações atualizadas com sucesso!', 'success')  # Definindo a mensagem flash como 'success'
    return redirect(request.referrer)

@app.route('/get_username', methods=['GET'])
def get_username():
    if 'username' not in session:
        return jsonify({"error": "Usuário não autenticado"})

    username = session['username']
    user = collection.find_one({"username": username}, {"_id": 0, "email": 1, "moradac": 1, "morada": 1, "nif": 1})

    if not user:
        return jsonify({"error": "Usuário não encontrado"})

    # Adiciona o nome de usuário aos dados retornados
    user['username'] = username

    return jsonify(user)

@app.route('/get_user_data', methods=['GET'])
def get_user_data():
    if 'username' not in session:
        return jsonify({"error": "Usuário não autenticado"})

    username = session['username']
    user = collection.find_one({"username": username}, {"_id": 0, "email": 1, "moradac": 1, "morada": 1, "nif": 1})

    if not user:
        return jsonify({"error": "Usuário não encontrado"})

    # Adiciona o nome de usuário aos dados retornados
    user['username'] = username

    return jsonify(user)


@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('username', None)
    flash('Você saiu com sucesso!')
    return redirect(url_for('home'))

# Diretório base do projeto
# Diretório base do projeto
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Caminho para o arquivo de banco de dados paletes
DATABASE = os.path.join(BASE_DIR, 'static', 'data', 'paletesdb.db')

# Caminho para o arquivo do banco de dados encomendas.db
DATABASE_ENCOMENDAS = os.path.join(BASE_DIR, 'static', 'data', 'userssells', 'encomendas.db')

def get_db():
   
    db = getattr(g, '_database', None)
    if db is None:
        try:
            db = g._database = sqlite3.connect(DATABASE)
        except sqlite3.Error as e:
            print(f"Erro ao conectar ao banco de dados: {e}")
    return db

def get_db_encomendas():
    
    db = getattr(g, '_database_encomendas', None)
    if db is None:
        try:
            db = g._database_encomendas = sqlite3.connect(DATABASE_ENCOMENDAS)
        except sqlite3.Error as e:
            print(f"Erro ao conectar ao banco de dados de encomendas: {e}")
    return db

def close_db(e=None):
    db = g.pop('_database', None)
    if db is not None:
        db.close()

    db_encomendas = g.pop('_database_encomendas', None)
    if db_encomendas is not None:
        db_encomendas.close()




from flask import jsonify
def get_id_from_tb_tipo(tipo_saco):
    try:
        conn = get_db()
        print("Conexão estabelecida com o banco de dados.")
        
        cursor = conn.cursor()
        
        query = "SELECT IDTipo FROM TBtipo WHERE [Tipo De Saco] = ?"
        print("Executando consulta:", query)
        cursor.execute(query, (tipo_saco,))
        
        result = cursor.fetchone()
        print("Resultado da consulta:", result)
        
        if result:
            id_tipo = result[0]
            print("ID do tipo encontrado:", id_tipo)
        else:
            id_tipo = -1  # Valor padrão para indicar que o ID não foi encontrado
            print("Tipo de saco não encontrado.")
        
        return id_tipo
    except Exception as e:
        print("Erro ao buscar ID do Tipo de Saco:", e)
        return -1
    


@app.route('/api/remover_produto/<int:id_produto>', methods=['DELETE'])
def remover_produto(id_produto):
    try:
        # Conecta-se ao banco de dados
        conn = get_db()
        cursor = conn.cursor()

        # Query para excluir o produto com o ID especificado
        delete_query = "DELETE FROM Produto WHERE IDProduto = ?"
        cursor.execute(delete_query, (id_produto,))
        conn.commit()

        return jsonify({"success": True}), 200
    except Exception as e:
        print("Erro ao remover produto:", e)
        return jsonify({"error": "Erro ao remover produto"}), 500
    finally:
        # Fecha a conexão com o banco de dados
        conn.close()



def get_id_from_tb_tamanho(tamanho):
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        query = "SELECT IDTamanho FROM TBtamanho WHERE [Tamanho] = ?"
        cursor.execute(query, (tamanho,))
        
        result = cursor.fetchone()
        
        if result:
            id_tamanho = result[0]
        else:
            id_tamanho = -1  # Valor padrão para indicar que o ID não foi encontrado
        
        return id_tamanho
    except Exception as e:
        print("Erro ao buscar ID do Tamanho:", e)
        return -1
   

def get_id_from_tb_cor(cor):
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        query = "SELECT IDCor FROM TBcor WHERE [Cor] = ?"
        cursor.execute(query, (cor,))
        
        result = cursor.fetchone()
        
        if result:
            id_cor = result[0]
        else:
            id_cor = -1  # Valor padrão para indicar que o ID não foi encontrado
        
        return id_cor
    except Exception as e:
        print("Erro ao buscar ID da Cor:", e)
        return -1
    

def get_id_from_tb_caixa(nome_cx):
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        query = "SELECT IDCaixa FROM TBcaixa WHERE [Nome] = ?"
        cursor.execute(query, (nome_cx,))
        
        result = cursor.fetchone()
        
        if result:
            id_caixa = result[0]
        else:
            id_caixa = -1  # Valor padrão para indicar que o ID não foi encontrado
        
        return id_caixa
    except Exception as e:
        print("Erro ao buscar ID da Caixa:", e)
        return -1

@app.route('/api/adicionar_produto', methods=['POST'])
def adicionar_produto():
    try:
        # Obter os dados enviados na solicitação POST
        data = request.json
        
        # Extrair os valores dos campos do JSON
        tipo_saco = data.get('tipo_saco')
        tamanho = data.get('tamanho')
        cor = data.get('cor')
        nome_caixa = data.get('nome_caixa')
        
        
        # Verificar se todos os campos foram preenchidos
        if tipo_saco and tamanho and cor and nome_caixa:
            # Obter IDs correspondentes para os valores selecionados nas comboboxes
            id_tipo = get_id_from_tb_tipo(tipo_saco)
            id_tamanho = get_id_from_tb_tamanho(tamanho)
            id_cor = get_id_from_tb_cor(cor)
            id_caixa = get_id_from_tb_caixa(nome_caixa)
            print("Tipo de Saco:", id_tipo)
            print("Tamanho:", id_tamanho)
            print("Cor:", id_cor)
            print("Nome da Caixa:", id_caixa)
            
            # Abre a conexão com o banco de dados
            conn = get_db()
            cursor = conn.cursor()
            
            # Inserir o novo produto na tabela Produto
            query = "INSERT INTO Produto (IDTipo, IDTamanho, IDCor, IDCaixa) VALUES (?, ?, ?, ?)"
            cursor.execute(query, (id_tipo, id_tamanho, id_cor, id_caixa))
            conn.commit()
            
            # Fechar a conexão com o banco de dados
            conn.close()
            
            # Retorna uma resposta de sucesso
            return jsonify({"success": True}), 200
        else:
            return jsonify({"error": "Por favor, preencha todas as informações do produto."}), 400
    except Exception as e:
        print("Erro ao adicionar produto:", e)
        return jsonify({"error": "Erro ao adicionar produto"}), 500

@app.route('/api/produtos')
def get_produtos():
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("""
    SELECT 
        Produto.IDProduto,
        TBtipo.[Tipo De Saco] AS TipoSaco,
        TBtamanho.[Tamanho] AS Tamanho,
        TBcor.[Cor] AS Cor,
        TBcaixa.[Nome] AS NomeCaixa
    FROM Produto
    INNER JOIN TBtipo ON Produto.IDTipo = TBtipo.IDTipo
    INNER JOIN TBtamanho ON Produto.IDTamanho = TBtamanho.IDTamanho
    INNER JOIN TBcor ON Produto.IDCor = TBcor.IDCor
    INNER JOIN TBcaixa ON Produto.IDCaixa = TBcaixa.IDCaixa;
""")
        # Recupere os nomes das colunas
        column_names = [desc[0] for desc in cursor.description]
        # Transforme os resultados em uma lista de dicionários
        produtos = [dict(zip(column_names, row)) for row in cursor.fetchall()]
        return jsonify(produtos)
    except Exception as e:
        print("Erro ao obter produtos:", e)
        return jsonify({"error": "Erro ao obter produtos"}), 500
    finally:
        conn.close()
@app.route('/api/tabelas')
def get_tabelas():
    try:
        conn = get_db()
        cursor = conn.cursor()

        # Consulta SQL para obter os nomes das tabelas do banco de dados
        query = "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';"
        cursor.execute(query)
        tabelas = [row[0] for row in cursor.fetchall()]

        return jsonify(tabelas)
    except Exception as e:
        print("Erro ao obter nomes das tabelas:", e)
        return jsonify([])  # Retorna uma lista vazia em caso de erro
    finally:
        conn.close()

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def obter_tipos_saco_do_banco():
    try:
        conn = get_db()
        cursor = conn.cursor()

        # Consulta SQL para obter os tipos de saco da tabela Produto
        query = """
        SELECT DISTINCT TBtipo.[Tipo De Saco]
        FROM Produto
        INNER JOIN TBtipo ON Produto.IDTipo = TBtipo.IDTipo
        """
        cursor.execute(query)
        tipos_saco = [row[0] for row in cursor.fetchall()]

        return tipos_saco
    except Exception as e:
        print("Erro ao obter os tipos de saco:", e)
        return []

def load_tamanho():
    try:
        conn = get_db()
        cursor = conn.cursor()

        # Consulta SQL para selecionar os tamanhos presentes na tabela TBtamanho
        query = """
        SELECT DISTINCT TBtamanho.[Tamanho]
        FROM Produto
        INNER JOIN TBtamanho ON Produto.IDTamanho = TBtamanho.IDTamanho
        """
        cursor.execute(query)
        tamanhos = [row[0] for row in cursor.fetchall()]

        return tamanhos
    except Exception as e:
        print("Erro ao carregar Tamanho:", e)
        return []
def load_cor(tipo_de_saco, tamanho):
    try:
        conn = get_db()
        cursor = conn.cursor()

        # Consulta SQL para selecionar as cores presentes na tabela Produto com base no tipo de saco e tamanho
        query = """
        SELECT DISTINCT TBcor.[Cor]
        FROM Produto
        INNER JOIN TBcor ON Produto.IDCor = TBcor.IDCor
        INNER JOIN TBtipo ON Produto.IDTipo = TBtipo.IDTipo
        INNER JOIN TBtamanho ON Produto.IDTamanho = TBtamanho.IDTamanho
        WHERE TBtipo.[Tipo De Saco] = ?
        AND TBtamanho.[Tamanho] = ?
        """
        cursor.execute(query, (tipo_de_saco, tamanho))
        cores = [row[0] for row in cursor.fetchall()]

        return cores
    except Exception as e:
        print("Erro ao carregar Cor:", e)
        return []
    
def obter_tipos_saco():
    check_db_path()
    print("aqui1")
    try:
        conn = get_db()
        cursor = conn.cursor()
        query = "SELECT [Tipo De Saco] FROM TBtipo"
        cursor.execute(query)
        tipos_saco = [row[0] for row in cursor.fetchall()]
        return tipos_saco
    except Exception as e:
        print("Erro ao obter tipos de saco:", e)
        return []

def obter_tamanhos():
    try:
        conn = get_db()
        cursor = conn.cursor()
        query = "SELECT [Tamanho] FROM TBtamanho"
        cursor.execute(query)
        tamanhos = [row[0] for row in cursor.fetchall()]
        return tamanhos
    except Exception as e:
        print("Erro ao obter tamanhos:", e)
        return []

def obter_cores():
    try:
        conn = get_db()
        cursor = conn.cursor()
        query = "SELECT [Cor] FROM TBcor"
        cursor.execute(query)
        cores = [row[0] for row in cursor.fetchall()]
        return cores
    except Exception as e:
        print("Erro ao obter cores:", e)
        return []
def obter_nomes_caixa():

    try:
        conn = get_db()
        cursor = conn.cursor()
        query = "SELECT [nome] FROM TBcaixa"
        cursor.execute(query)
        nomes_caixa = [row[0] for row in cursor.fetchall()]
        return nomes_caixa
    except Exception as e:
        print("Erro ao obter nomes das caixas:", e)
        return []

@app.route('/get_cores')
def get_cores():
    tipo_de_saco = request.args.get('tipo_de_saco')
    tamanho = request.args.get('tamanho')

    if not tipo_de_saco or not tamanho:
        return jsonify({'error': 'Parâmetros inválidos'}), 400

    cores = load_cor(tipo_de_saco, tamanho)
    return jsonify({'cores': cores})

@app.route('/get_artigo', methods=['POST'])
def get_artigo():
    data = request.get_json()
    tipo_de_saco = data.get('tipo_de_saco')
    tamanho = data.get('tamanho')
    cor = data.get('cor')

    try:
        conn = get_db()
        cursor = conn.cursor()

        # Consulta SQL para selecionar o Artigo com base nas seleções nas comboboxes
        query = """
        SELECT Produto.Artigo
        FROM Produto
        INNER JOIN TBtipo ON Produto.IDTipo = TBtipo.IDTipo
        INNER JOIN TBtamanho ON Produto.IDTamanho = TBtamanho.IDTamanho
        INNER JOIN TBcor ON Produto.IDCor = TBcor.IDCor
        WHERE TBtipo.[Tipo De Saco] = ?
        AND TBtamanho.[Tamanho] = ?
        AND TBcor.[Cor] = ?
        """
        cursor.execute(query, (tipo_de_saco, tamanho, cor))
        result = cursor.fetchone()

        if result:
            artigo = result[0]
            return jsonify({'artigo': artigo})
        else:
            return jsonify({'error': 'Produto não encontrado'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/get_caixa_quantidade', methods=['POST'])
def get_caixa_quantidade():
    data = request.get_json()
    tipo_de_saco = data.get('tipo_de_saco')
    tamanho = data.get('tamanho')
    cor = data.get('cor')

    try:
        conn = get_db()
        cursor = conn.cursor()

        # Consulta SQL para selecionar o IDCaixa com base nas seleções nas comboboxes
        query = """
        SELECT Produto.IDCaixa
        FROM Produto
        INNER JOIN TBtipo ON Produto.IDTipo = TBtipo.IDTipo
        INNER JOIN TBtamanho ON Produto.IDTamanho = TBtamanho.IDTamanho
        INNER JOIN TBcor ON Produto.IDCor = TBcor.IDCor
        WHERE TBtipo.[Tipo De Saco] = ?
        AND TBtamanho.[Tamanho] = ?
        AND TBcor.[Cor] = ?
        """
        cursor.execute(query, (tipo_de_saco, tamanho, cor))
        result = cursor.fetchone()

        if result:
            id_caixa = result[0]

            # Consulta SQL para buscar a quantidade na tabela TBcaixa com base no IDCaixa
            quantidade_query = "SELECT Quantidade FROM TBcaixa WHERE IDCaixa = ?"
            cursor.execute(quantidade_query, (id_caixa,))
            quantidade_result = cursor.fetchone()

            if quantidade_result:
                quantidade = quantidade_result[0]
                return jsonify({'quantidade': quantidade})
            else:
                return jsonify({'error': 'Quantidade não encontrada'}), 404
        else:
            return jsonify({'error': 'Produto não encontrado'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def consultar_medidas_caixa(id_caixa):
    medidas_caixa = []

    # Consulta SQL para obter as medidas da caixa na base de dados usando o IDCaixa
    query = "SELECT Comp, Larg, Alt FROM TBcaixa WHERE IDCaixa = ?"
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(query, (id_caixa,))
        rows = cursor.fetchall()

        for row in rows:
            comprimento = float(row[0])
            largura = float(row[1])
            altura = float(row[2])
            medidas_caixa.append((comprimento, largura, altura))

    except Exception as e:
        print("Erro ao consultar medidas da caixa:", e)

    return medidas_caixa

@app.route('/get_medidas_caixa', methods=['POST'])
def get_medidas_caixa():
    data = request.get_json()
    tipo_de_saco = data.get('tipo_de_saco')
    tamanho = data.get('tamanho')
    cor = data.get('cor')

    try:
        id_caixa = obter_id_caixa(tipo_de_saco, tamanho, cor)

        if id_caixa != -1:
            medidas_caixa = consultar_medidas_caixa(id_caixa)
            return jsonify({'medidas_caixa': medidas_caixa})
        else:
            return jsonify({'error': 'ID da caixa não encontrado'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def obter_id_caixa(tipo, tamanho, cor):
    id_caixa = -1

    try:
        conn = get_db()
        cursor = conn.cursor()

        # Consulta SQL para selecionar o IDCaixa com base nas seleções nas comboboxes
        query = """
                SELECT Produto.IDCaixa
                FROM Produto
                INNER JOIN TBtipo ON Produto.IDTipo = TBtipo.IDTipo
                INNER JOIN TBtamanho ON Produto.IDTamanho = TBtamanho.IDTamanho
                INNER JOIN TBcor ON Produto.IDCor = TBcor.IDCor
                WHERE TBtipo.[Tipo De Saco] = ?
                AND TBtamanho.[Tamanho] = ?
                AND TBcor.[Cor] = ?
                """

        cursor.execute(query, (tipo, tamanho, cor))
        row = cursor.fetchone()

        if row:
            id_caixa = row[0]

    except Exception as ex:
        print("Erro ao obter ID da caixa:", ex)

    return id_caixa



@app.route('/')
@app.route('/home')
def home():
    isAdmin = session.get('isAdmin', False)
    logged_in = session.get('logged_in', False)
    return render_template('index.html', logged_in=logged_in, isAdmin=isAdmin, title='Home Page')


@app.route('/paletes', methods=['GET', 'POST'])
def paletes():
    if not session.get('logged_in'):
        flash('Você precisa estar logado para acessar esta página.', 'danger')
        return redirect(url_for('home'))
    
    if not session.get('access_paletes'):
        flash('Você não tem permissão para acessar esta página.', 'danger')
        return redirect(url_for('home'))
    
    isAdmin = session.get('isAdmin', False)

    if request.method == 'POST':
        # Lógica para processar o formulário enviado
        data = request.get_json()
        to_emails = data.get('to')
        subject = data.get('subject')
        body = data.get('body')
        # Aqui você pode chamar a função send_email com o conteúdo do email
        for to_email in to_emails:
            send_email(to_email, subject, body, is_html=True)

        return "Email enviado com sucesso!"  # Ou redirecionar para outra página
        
    else:
        print("hello")
        tipo_de_saco = request.args.get('tipo_de_saco')
        tamanho = request.args.get('tamanho')
        
        tipos_saco = obter_tipos_saco_do_banco()
        tamanhos = load_tamanho()
        cores = load_cor(tipo_de_saco, tamanho) if tipo_de_saco and tamanho else []
        logged_in = session.get('logged_in', False)
        return render_template('paletes.html', tipos_saco=tipos_saco, isAdmin=isAdmin, tamanhos=tamanhos, cores=cores, logged_in=logged_in, title='Paletes')



@app.route('/settingsmaster')
def settingsmaster():
    isAdmin = session.get('isAdmin', False)

    if not session.get('logged_in'):
        flash('Você precisa estar logado para acessar esta página.', 'danger')
        return redirect(url_for('home'))
    
    if not session.get('isAdmin'):
        flash('Você não tem permissão para acessar esta página.', 'danger')
        return redirect(url_for('home'))

    tipos_saco = obter_tipos_saco()
    tamanhos = obter_tamanhos()
    cores = obter_cores()
    nomes_caixa = obter_nomes_caixa()
    logged_in = session.get('logged_in', False)
    return render_template('settingsmaster.html', title='settingsmaster', tipos_saco=tipos_saco, isAdmin=isAdmin, tamanhos=tamanhos, cores=cores, nomes_caixa=nomes_caixa, logged_in=logged_in)


@app.route('/encomendasgerir')
def encomendasgerir():
    isAdmin = session.get('isAdmin', False)

    if not session.get('logged_in'):
        flash('Você precisa estar logado para acessar esta página.', 'danger')
        return redirect(url_for('home'))
    
    if not session.get('isAdmin'):
        flash('Você não tem permissão para acessar esta página.', 'danger')
        return redirect(url_for('home'))

    
    logged_in = session.get('logged_in', False)
    return render_template('encomendasgerir.html', title='Gestão de Encomendas', isAdmin=isAdmin, logged_in=logged_in)

@app.route('/accountsettings')
def accountsettings():
    if 'username' not in session:
        flash('Você precisa estar logado para acessar esta página.')
        return redirect(url_for('home'))
    
    isAdmin = session.get('isAdmin', False)

    username = session['username']
    user = collection.find_one({"username": username})

    if not user:
        flash('Usuário não encontrado.')
        return redirect(url_for('home'))

    # Print the user value to debug
    print("Valor do usuário:", user)
    
    return render_template('accountsettings.html', user=user, isAdmin=isAdmin, logged_in=True, title='Account Settings')

@app.route('/ferramenta_preco')
def ferramenta_preco():
    if not session.get('logged_in'):
        flash('Você precisa estar logado para acessar esta página.')
        return redirect(url_for('home'))
    
    access_ferramenta_preco = session.get('access_ferramenta_preco')
    print("Valor de access_ferramenta_preco:", access_ferramenta_preco)  # Adiciona esta linha
    
    if not access_ferramenta_preco:
        flash('Você não tem permissão para acessar esta página.')
        return redirect(url_for('home'))
    
    isAdmin = session.get('isAdmin', False)
    logged_in = session.get('logged_in', False)
    return render_template('ferramenta_preco.html', logged_in=logged_in, isAdmin=isAdmin, title='ferramenta_preco')

@app.route('/encomendas')
def encomendas():
    if not session.get('logged_in'):
        flash('Você precisa estar logado para acessar esta página.')
        return redirect(url_for('home'))
    
    access_encomendas = session.get('access_encomendas')
    print("Valor de access_encomendas:", access_encomendas)  # Adiciona esta linha
    
    if not access_encomendas:
        flash('Você não tem permissão para acessar esta página.')
        return redirect(url_for('home'))
   
    isAdmin = session.get('isAdmin', False)
    logged_in = session.get('logged_in', False)
    return render_template('encomendas.html', logged_in=logged_in, isAdmin=isAdmin, title='encomendas')

@app.route('/gerir_db')
def gerir_db():

    isAdmin = session.get('isAdmin', False)


    tipos_saco = obter_tipos_saco()
    tamanhos = obter_tamanhos()
    cores = obter_cores()
    nomes_caixa = obter_nomes_caixa()
    logged_in = session.get('logged_in', False)
    return render_template('gerir_db.html', tipos_saco=tipos_saco, isAdmin=isAdmin, tamanhos=tamanhos, cores=cores, nomes_caixa=nomes_caixa, logged_in=logged_in, title='gerir_db')



if __name__ == '__main__':
    app.run(debug=True)
