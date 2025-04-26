import os
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
#from supabase import create_client, Client
from dotenv import load_dotenv
from flask_wtf.csrf import CSRFProtect
from supabase import create_client, ClientOptions
# Initialisation de l'application
app = Flask(__name__)

# Configuration
load_dotenv()
app.secret_key = os.getenv('FLASK_SECRET_KEY', os.urandom(24))
app.config['UPLOAD_FOLDER'] = 'uploads/pem_files'
app.config['ALLOWED_EXTENSIONS'] = {'pem'}
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max

# Protection CSRF
csrf = CSRFProtect(app)

# Supabase Client
#supabase = create_client(os.getenv('SUPABASE_URL'), os.getenv('SUPABASE_KEY'))

from supabase import create_client, ClientOptions
import os

# Configuration pour les nouvelles versions
supabase = create_client(
    supabase_url=os.getenv('SUPABASE_URL'),
    supabase_key=os.getenv('SUPABASE_KEY'),
    options=ClientOptions(
        auto_refresh_token=True,
        persist_session=True,
        storage=None
    )
)

def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


def create_test_users():
    """Fonction pour créer les utilisateurs de test (à exécuter une fois)"""
    test_users = [
        {'email': 'demo@example.com', 'password': 'password', 'role': 'user'},
        {'email': 'admin@example.com', 'password': 'password', 'role': 'admin'}
    ]

    for user in test_users:
        res = supabase.table('users').select('id').eq('email', user['email']).execute()
        if not res.data:
            supabase.table('users').insert({
                'email': user['email'],
                'password_hash': generate_password_hash(user['password']),
                'role': user['role']
            }).execute()


@app.route("/")
def home():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template("index.html")


@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()

        try:
            res = supabase.table('users').select('*').eq('email', email).execute()
            if len(res.data) == 1 and check_password_hash(res.data[0]['password_hash'], password):
                session['user_id'] = res.data[0]['id']
                session['email'] = res.data[0]['email']
                session['role'] = res.data[0]['role']
                flash('Connexion réussie!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Email ou mot de passe incorrect', 'danger')
        except Exception as e:
            flash('Erreur lors de la connexion', 'danger')
            app.logger.error(f"Login error: {str(e)}")

    return render_template("login.html")


@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    try:
        if session.get('role') == 'admin':
            files = supabase.table('pem_files').select('*').execute()
        else:
            files = supabase.table('pem_files').select('*').eq('user_id', session['user_id']).execute()

        return render_template("dashboard.html",
                               pem_files=files.data,
                               is_admin=session.get('role') == 'admin')
    except Exception as e:
        flash('Erreur lors du chargement des fichiers', 'danger')
        app.logger.error(f"Dashboard error: {str(e)}")
        return render_template("dashboard.html", pem_files=[])


@app.route('/add-pem', methods=['GET', 'POST'])
def add_pem():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        file = request.files.get('pem_file')
        file_name = request.form.get('file_name', '').strip()
        description = request.form.get('description', '').strip()

        if not file or not allowed_file(file.filename):
            flash('Fichier .pem requis', 'danger')
            return redirect(request.url)

        if not file_name:
            flash('Nom de fichier requis', 'danger')
            return redirect(request.url)

        try:
            # Vérifier si le nom existe déjà
            existing = supabase.table('pem_files').select('id').eq('file_name', file_name).execute()
            if existing.data:
                flash('Un fichier avec ce nom existe déjà', 'danger')
                return redirect(request.url)

            # Sauvegarder le fichier
            filename = secure_filename(f"{file_name}.pem")
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)

            # Enregistrer dans Supabase
            supabase.table('pem_files').insert({
                'user_id': session['user_id'],
                'file_name': file_name,
                'file_path': filename,
                'description': description
            }).execute()

            flash('Fichier PEM ajouté avec succès!', 'success')
            return redirect(url_for('dashboard'))

        except Exception as e:
            flash("Erreur lors de l'ajout du fichier", 'danger')
            app.logger.error(f"Add PEM error: {str(e)}")

    return render_template('add_pem.html')


@app.route('/download/<filename>')
def download_file(filename):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    try:
        # Vérifier que l'utilisateur a le droit d'accéder à ce fichier
        if session.get('role') != 'admin':
            res = supabase.table('pem_files').select('user_id').eq('file_path', filename).execute()
            if not res.data or res.data[0]['user_id'] != session['user_id']:
                flash('Accès non autorisé', 'danger')
                return redirect(url_for('dashboard'))

        return send_from_directory(
            app.config['UPLOAD_FOLDER'],
            filename,
            as_attachment=True
        )
    except Exception as e:
        flash('Erreur lors du téléchargement', 'danger')
        app.logger.error(f"Download error: {str(e)}")
        return redirect(url_for('dashboard'))


@app.route('/delete/<filename>')
def delete_file(filename):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if session.get('role') != 'admin':
        flash('Action non autorisée - Admin seulement', 'danger')
        return redirect(url_for('dashboard'))

    try:
        # Supprimer le fichier physique
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        if os.path.exists(filepath):
            os.remove(filepath)

        # Supprimer de Supabase
        supabase.table('pem_files').delete().eq('file_path', filename).execute()

        flash('Fichier supprimé avec succès', 'success')
    except Exception as e:
        flash('Erreur lors de la suppression', 'danger')
        app.logger.error(f"Delete error: {str(e)}")

    return redirect(url_for('dashboard'))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for('home'))


@app.after_request
def add_header(response):
    """Empêcher le caching des pages sensibles"""
    if 'user_id' in session:
        response.headers['Cache-Control'] = 'no-store, must-revalidate'
    return response


if __name__ == "__main__":
    with app.app_context():
        #create_test_users()  # À désactiver après la première exécution
        app.run(debug=os.getenv('FLASK_DEBUG', 'False') == 'True')