from flask import Flask, request, render_template, redirect, url_for, session
import mysql.connector
import bcrypt
import mercadopago
import os

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'sua_chave_secreta_aqui')

# Credenciais do Mercado Pago
MERCADO_PAGO_PUBLIC_KEY = os.getenv('MERCADO_PAGO_PUBLIC_KEY', "APP_USR-5027b829-8b4e-47ab-a603-15f4011e50a5")
MERCADO_PAGO_ACCESS_TOKEN = os.getenv('MERCADO_PAGO_ACCESS_TOKEN', "APP_USR-2957403152017240-091400-a4ac3b9b1025c4dce0447d24868e088e-657641042")

# Configuração da API do Mercado Pago
sdk = mercadopago.SDK(MERCADO_PAGO_ACCESS_TOKEN)

# Configurações do banco de dados MySQL
DATABASE_CONFIG = {
    'user': os.getenv('DB_USER', 'bf4f36ce29443b'),  # Substitua com seu usuário
    'password': os.getenv('DB_PASSWORD', '6b0486f7'),  # Substitua com sua senha
    'host': os.getenv('DB_HOST', 'us-cluster-east-01.k8s.cleardb.net'),  # Host do banco ClearDB
    'database': os.getenv('DB_NAME', 'heroku_c37d1ea8733062b'),  # Nome do banco de dados
    'raise_on_warnings': True,
}

def get_db_connection():
    return mysql.connector.connect(**DATABASE_CONFIG)

def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def check_password(stored_hash, password):
    return bcrypt.checkpw(password.encode(), stored_hash.encode())

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('user_balance'))

    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        full_name = request.form['full_name']
        age = request.form['age']
        phone = request.form['phone']
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']  # Adicionando o campo de email

        # Valida se todos os campos estão preenchidos
        if not all([full_name, age, phone, username, password, email]):
            return 'Todos os campos são obrigatórios', 400

        conn = get_db_connection()
        cur = conn.cursor(dictionary=True)
        cur.execute('SELECT * FROM users WHERE username = %s OR email = %s', (username, email))
        user = cur.fetchone()

        if user:
            cur.close()
            conn.close()
            return 'Usuário ou email já existe', 400

        hashed_password = hash_password(password)
        default_balance = 0.0  # Saldo padrão para novos usuários

        cur.execute('''INSERT INTO users (username, password_hash, email, full_name, age, phone, balance)
                       VALUES (%s, %s, %s, %s, %s, %s, %s)''', 
                    (username, hashed_password, email, full_name, age, phone, default_balance))

        conn.commit()
        cur.close()
        conn.close()

        return redirect(url_for('index'))

    return render_template('register.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']

    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)
    cur.execute('SELECT id, password_hash FROM users WHERE username = %s', (username,))
    user = cur.fetchone()
    cur.close()
    conn.close()

    if user and check_password(user['password_hash'], password):
        session['user_id'] = user['id']
        return redirect(url_for('user_balance'))
    return 'Usuário ou senha incorretos', 401

@app.route('/user/balance', methods=['GET'])
def user_balance():
    if 'user_id' not in session:
        return redirect(url_for('index'))

    user_id = session['user_id']
    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)
    cur.execute('SELECT balance FROM users WHERE id = %s', (user_id,))
    user = cur.fetchone()
    balance = user['balance']
    cur.close()
    conn.close()

    return render_template('user_balance.html', balance=balance)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)

