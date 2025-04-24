import os
basedir = os.path.abspath(os.path.dirname(__file__))

class Config:
    # Secret key for session management and CSRF protection
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'hard-to-guess-string'
    
    # Database configuration
    SQLALCHEMY_DATABASE_URI = SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://root:admin@localhost/jobsite_db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Upload folder for resumes
    UPLOAD_FOLDER = os.path.join(basedir, 'app/static/uploads')
    
    # Allowed extensions for resume uploads
    ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx'} 