from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from config import Config
import pymysql
import os

# Initialize extensions
db = SQLAlchemy()
migrate = Migrate()  # 不要在这里传递 app 和 db
login_manager = LoginManager()
login_manager.login_view = 'auth.login'
login_manager.login_message = 'Please log in to access this page.'

def create_app(config_class=Config):
    # Create and configure the app
    app = Flask(__name__)
    app.config.from_object(config_class)
    
    # Initialize extensions with the app
    pymysql.install_as_MySQLdb()  # 这行让pymysql作为MySQLdb的替代品
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    
    # Register blueprints
    from app.routes import main_bp, auth_bp, user_bp, admin_bp
    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(user_bp, url_prefix='/user')
    app.register_blueprint(admin_bp, url_prefix='/admin')
    
    # Create upload folder if it doesn't exist
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    
    @app.template_filter('nl2br')
    def nl2br(value):
        """Convert newlines to HTML line breaks."""
        if value:
            return value.replace('\n', '<br>')
        return value
    
    return app 