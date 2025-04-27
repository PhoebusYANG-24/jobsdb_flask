from app import db, login_manager
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin

# User roles
class Role:
    USER = 'user'
    ADMIN = 'admin'

class User(UserMixin, db.Model):
    """User model for job seekers and admins"""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, index=True)
    email = db.Column(db.String(120), unique=True, index=True)
    password_hash = db.Column(db.String(512))
    role = db.Column(db.String(10), default=Role.USER)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    resumes = db.relationship('Resume', backref='user', lazy='dynamic')
    applications = db.relationship('Application', backref='applicant', lazy='dynamic')
    
    def __init__(self, username, email, password, role=Role.USER):
        self.username = username
        self.email = email
        self.password_hash = generate_password_hash(password)
        self.role = role
    
    def check_password(self, password):
        """Check if the provided password matches the stored hash"""
        return check_password_hash(self.password_hash, password)
    
    def is_admin(self):
        """Check if the user has admin role"""
        return self.role == Role.ADMIN
    
    def __repr__(self):
        return f'<User {self.username}>'

    def has_applied_to(self, job_id):
        """Check if the user has already applied to a specific job"""
        return Application.query.filter_by(
            user_id=self.id,
            job_id=job_id
        ).first() is not None

    def set_password(self, password):
        """Set password for user"""
        self.password_hash = generate_password_hash(password)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class Company(db.Model):
    """company information model"""
    __tablename__ = 'companies'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), unique=True, nullable=False)
    description = db.Column(db.Text)
    address = db.Column(db.String(200))
    website = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    # Related positions
    jobs = db.relationship('Job', backref='employer', lazy='dynamic')

    def __repr__(self):
        return f'<Company {self.name}>'

class CompanyTag(db.Model):
    """Company and label association model"""
    __tablename__ = 'company_tags'
    id = db.Column(db.Integer, primary_key=True)
    company_id = db.Column(db.Integer, db.ForeignKey('companies.id'), nullable=False)
    tag_id = db.Column(db.Integer, db.ForeignKey('tags.id'), nullable=False)

    def __repr__(self):
        return f'<CompanyTag Company:{self.company_id} Tag:{self.tag_id}>'

class Follow(db.Model):
    """Users focus on company models"""
    __tablename__ = 'follows'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    company_id = db.Column(db.Integer, db.ForeignKey('companies.id'), nullable=False)
    followed_at = db.Column(db.DateTime, default=datetime.utcnow)
    # Associated users
    user = db.relationship('User', backref='followed_companies', lazy='joined')
    # Related companies
    company = db.relationship('Company', backref='followers', lazy='joined')

    def __repr__(self):
        return f'<Follow User:{self.user_id} Company:{self.company_id}>'

class Job(db.Model):
    """Job posting model"""
    __tablename__ = 'jobs'
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text(65535), nullable=False)
    requirements = db.Column(db.Text, nullable=False)
    location = db.Column(db.String(100), nullable=False)
    salary = db.Column(db.String(50), nullable=False)
    contact_info = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    posted_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    
    # Relationships
    applications = db.relationship('Application', backref='job_list', lazy='dynamic')
    poster_user = db.relationship('User', foreign_keys=[posted_by], backref='posted_jobs')
    
    def __repr__(self):
        return f'<Job {self.title}>'

class JobTag(db.Model):
    """The association model between positions and tags"""
    __tablename__ = 'job_tags'
    id = db.Column(db.Integer, primary_key=True)
    job_id = db.Column(db.Integer, db.ForeignKey('jobs.id'), nullable=False)
    tag_id = db.Column(db.Integer, db.ForeignKey('tags.id'), nullable=False)

    def __repr__(self):
        return f'<JobTag Job:{self.job_id} Tag:{self.tag_id}>'

class Resume(db.Model):
    """Resume model for job seekers"""
    __tablename__ = 'resumes'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    name = db.Column(db.String(64), nullable=False)
    gender = db.Column(db.String(10), nullable=False)
    age = db.Column(db.Integer, nullable=False)
    education = db.Column(db.String(100), nullable=False)
    contact = db.Column(db.String(100), nullable=False)
    experience = db.Column(db.Text, nullable=False)
    introduction = db.Column(db.Text(16777215), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    applications = db.relationship('Application', backref='resume', lazy='dynamic')
    
    def __repr__(self):
        return f'<Resume {self.name}>'

class Skill(db.Model):
    """Skill label model"""
    __tablename__ = 'skills'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True, nullable=False)
    # Related resume
    resumes = db.relationship('ResumeSkill', backref='skill', lazy='dynamic')
    # Related positions
    jobs = db.relationship('JobSkill', backref='skill', lazy='dynamic')

    def __repr__(self):
        return f'<Skill {self.name}>'

class ResumeSkill(db.Model):
    """Resume and skills association model"""
    __tablename__ = 'resume_skills'
    id = db.Column(db.Integer, primary_key=True)
    resume_id = db.Column(db.Integer, db.ForeignKey('resumes.id'), nullable=False)
    skill_id = db.Column(db.Integer, db.ForeignKey('skills.id'), nullable=False)
    proficiency = db.Column(db.String(20))  # proficiency

    def __repr__(self):
        return f'<ResumeSkill Resume:{self.resume_id} Skill:{self.skill_id}>'

class JobSkill(db.Model):
    """The correlation model between positions and skills"""
    __tablename__ = 'job_skills'
    id = db.Column(db.Integer, primary_key=True)
    job_id = db.Column(db.Integer, db.ForeignKey('jobs.id'), nullable=False)
    skill_id = db.Column(db.Integer, db.ForeignKey('skills.id'), nullable=False)

    def __repr__(self):
        return f'<JobSkill Job:{self.job_id} Skill:{self.skill_id}>'


class Application(db.Model):
    """Application model connecting users, jobs, and resumes"""
    __tablename__ = 'applications'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    job_id = db.Column(db.Integer, db.ForeignKey('jobs.id'), nullable=False)
    resume_id = db.Column(db.Integer, db.ForeignKey('resumes.id'), nullable=False)
    status = db.Column(db.Enum('Pending', 'Reviewed', 'Accepted', 'Rejected', name='application_status'), 
                      default='Pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f'<Application {self.id}>' 

class Interview(db.Model):
    """Interview scheduling model"""
    __tablename__ = 'interviews'
    id = db.Column(db.Integer, primary_key=True)
    application_id = db.Column(db.Integer, db.ForeignKey('applications.id'), nullable=False)
    interviewer_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    interview_time = db.Column(db.DateTime, nullable=False)
    location = db.Column(db.String(200))
    status = db.Column(db.Enum('Scheduled', 'Completed', 'Cancelled', name='interview_status'), default='Scheduled')
    # Related application
    application = db.relationship('Application', backref='interviews', lazy='joined')
    # Associated interviewer
    interviewer = db.relationship('User', backref='interviewed_applications', lazy='joined')

    def __repr__(self):
        return f'<Interview {self.id}>'

class Message(db.Model):
    """Message model, used for communication between users, interviewers, and companies"""
    __tablename__ = 'messages'
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    subject = db.Column(db.String(120))
    content = db.Column(db.Text)
    sent_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)
    # Associated sender
    sender = db.relationship('User', foreign_keys=[sender_id], backref='sent_messages', lazy='joined')
    # Associated recipient
    receiver = db.relationship('User', foreign_keys=[receiver_id], backref='received_messages', lazy='joined')

    def __repr__(self):
        return f'<Message {self.id} Subject:{self.subject}>'

class Rating(db.Model):
    """Interview scoring model"""
    __tablename__ = 'ratings'
    id = db.Column(db.Integer, primary_key=True)
    interview_id = db.Column(db.Integer, db.ForeignKey('interviews.id'), nullable=False)
    score = db.Column(db.Integer, nullable=False)
    comment = db.Column(db.Text)
    # Related interviews
    interview = db.relationship('Interview', backref='ratings', lazy='joined')
    
class Tag(db.Model):
    """A general label model that can be used to classify positions, companies, etc."""
    __tablename__ = 'tags'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True, nullable=False)
    # Related positions
    jobs = db.relationship('JobTag', backref='tag', lazy='dynamic')
    # Related companies
    companies = db.relationship('CompanyTag', backref='tag', lazy='dynamic')

    def __repr__(self):
        return f'<Tag {self.name}>'
