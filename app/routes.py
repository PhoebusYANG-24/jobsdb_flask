from flask import Blueprint, render_template, redirect, url_for, flash, request, current_app, jsonify
from flask_login import login_user, logout_user, login_required, current_user
from app import db
from app.models import User, Job, Resume, Application, Role
from app.forms import LoginForm, RegistrationForm, JobForm, ResumeForm, JobSearchForm, EditProfileForm, ChangePasswordForm
from werkzeug.utils import secure_filename
import os
from datetime import datetime, timedelta
from sqlalchemy import or_
import json

# Blueprint definitions
main_bp = Blueprint('main', __name__)
auth_bp = Blueprint('auth', __name__)
user_bp = Blueprint('user', __name__)
admin_bp = Blueprint('admin', __name__)

# Main routes
@main_bp.route('/')
def index():
    """Home page with latest job listings"""
    jobs = Job.query.order_by(Job.created_at.desc()).limit(10).all()
    return render_template('home.html', jobs=jobs)

@main_bp.route('/search', methods=['GET', 'POST'])
def search():
    """Search for jobs"""
    form = JobSearchForm()
    jobs = []
    
    if form.validate_on_submit() or request.args.get('title'):
        # Get search parameters
        title = form.title.data or request.args.get('title', '')
        location = form.location.data or request.args.get('location', '')
        salary = form.salary.data or request.args.get('salary', '')
        
        # Build query
        query = Job.query
        
        if title:
            query = query.filter(Job.title.ilike(f'%{title}%'))
        if location:
            query = query.filter(Job.location.ilike(f'%{location}%'))
        if salary:
            query = query.filter(Job.salary.ilike(f'%{salary}%'))
        
        jobs = query.order_by(Job.created_at.desc()).all()
    
    return render_template('search.html', form=form, jobs=jobs)

@main_bp.route('/job/<int:job_id>')
def job_details(job_id):
    """View details of a specific job"""
    job = Job.query.get_or_404(job_id)
    

    similar_jobs = Job.query.filter(
        (Job.location == job.location) | 
        (Job.title.like(f'%{job.title.split()[0]}%')),
        Job.id != job.id
    ).limit(3).all()
    
    return render_template('job_details.html', job=job, similar_jobs=similar_jobs)

# Authentication routes
@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """User login"""
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            next_page = request.args.get('next')
            if user.is_admin():
                return redirect(next_page or url_for('admin.dashboard'))
            return redirect(next_page or url_for('main.index'))
        flash('Invalid email or password')
    
    return render_template('auth/login.html', form=form)

@auth_bp.route('/logout')
@login_required
def logout():
    """User logout"""
    logout_user()
    return redirect(url_for('main.index'))

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    """User registration"""
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(
            username=form.username.data,
            email=form.email.data,
            password=form.password.data
        )
        db.session.add(user)
        db.session.commit()
        flash('Registration successful! You can now log in.')
        return redirect(url_for('auth.login'))
    
    return render_template('auth/register.html', form=form)

# User routes
@user_bp.route('/profile')
@login_required
def profile():
    """User profile page"""
    from app.models import Application  # 导入 Application 模型
    
    return render_template('user/profile.html', Application=Application)

@user_bp.route('/resume')
@login_required
def resume():
    """View or edit resume"""
    user_resume = Resume.query.filter_by(user_id=current_user.id).first()
    form = ResumeForm()
    
    if user_resume:
        form.name.data = user_resume.name
        form.gender.data = user_resume.gender
        form.age.data = user_resume.age
        form.education.data = user_resume.education
        form.contact.data = user_resume.contact
        form.experience.data = user_resume.experience
        form.introduction.data = user_resume.introduction
    
    return render_template('user/resume.html', form=form, resume=user_resume)

@user_bp.route('/resume/create', methods=['POST'])
@login_required
def create_resume():
    """Create or update resume"""
    form = ResumeForm()
    if form.validate_on_submit():
        user_resume = Resume.query.filter_by(user_id=current_user.id).first()
        
        if user_resume:
            # Update existing resume
            user_resume.name = form.name.data
            user_resume.gender = form.gender.data
            user_resume.age = form.age.data
            user_resume.education = form.education.data
            user_resume.contact = form.contact.data
            user_resume.experience = form.experience.data
            user_resume.introduction = form.introduction.data
            user_resume.updated_at = datetime.utcnow()
            flash('Your resume has been updated!')
        else:
            # Create new resume
            new_resume = Resume(
                user_id=current_user.id,
                name=form.name.data,
                gender=form.gender.data,
                age=form.age.data,
                education=form.education.data,
                contact=form.contact.data,
                experience=form.experience.data,
                introduction=form.introduction.data
            )
            db.session.add(new_resume)
            flash('Your resume has been created!')
        
        db.session.commit()
        return redirect(url_for('user.profile'))
    
    return redirect(url_for('user.resume'))

@user_bp.route('/apply/<int:job_id>', methods=['GET', 'POST'])
@login_required
def apply_job(job_id):
    """Apply for a job"""
    job = Job.query.get_or_404(job_id)
    resume = Resume.query.filter_by(user_id=current_user.id).first()
    
    if not resume:
        flash('You need to create a resume before applying for jobs.')
        return redirect(url_for('user.create_resume'))
    
    # Check if already applied
    existing_application = Application.query.filter_by(
        user_id=current_user.id,
        job_id=job_id
    ).first()
    
    if existing_application:
        flash('You have already applied for this job.')
        return redirect(url_for('main.job_details', job_id=job_id))
    
    # Create new application
    application = Application(
        user_id=current_user.id,
        job_id=job_id,
        resume_id=resume.id
    )
    db.session.add(application)
    db.session.commit()
    
    flash('Application submitted successfully!')
    return redirect(url_for('user.applications'))

@user_bp.route('/applications')
@login_required
def applications():
    """View user's job applications"""
    applications = Application.query.filter_by(user_id=current_user.id).order_by(Application.created_at.desc()).all()
    return render_template('user/applications.html', applications=applications)

@user_bp.route('/profile/edit', methods=['GET', 'POST'])
@login_required
def edit_profile():
    """Edit user profile"""
    form = EditProfileForm(obj=current_user)
    
    if form.validate_on_submit():

        if form.username.data != current_user.username and User.query.filter_by(username=form.username.data).first():
            flash('This username is already taken.')
            return render_template('user/edit_profile.html', form=form)
        

        current_user.username = form.username.data
        current_user.email = form.email.data
        db.session.commit()
        
        flash('Your profile has been updated.')
        return redirect(url_for('user.profile'))
    
    return render_template('user/edit_profile.html', form=form)

@user_bp.route('/profile/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    """Change user password"""
    form = ChangePasswordForm()
    
    if form.validate_on_submit():

        if not current_user.check_password(form.current_password.data):
            flash('Current password is incorrect.')
            return render_template('user/change_password.html', form=form)
        

        current_user.set_password(form.new_password.data)
        db.session.commit()
        
        flash('Your password has been updated.')
        return redirect(url_for('user.profile'))
    
    return render_template('user/change_password.html', form=form)

# Admin routes
@admin_bp.route('/dashboard')
@login_required
def dashboard():
    """Admin dashboard"""
    if not current_user.is_admin():
        flash('Access denied. Admin privileges required.')
        return redirect(url_for('main.index'))
    

    job_count = Job.query.count()
    user_count = User.query.count()
    application_count = Application.query.count()
    accepted_count = Application.query.filter_by(status='Accepted').count()
    

    application_data = []
    for i in range(7, 0, -1):
        date = datetime.utcnow() - timedelta(days=i*5)
        count = Application.query.filter(
            Application.created_at >= date.replace(hour=0, minute=0, second=0),
            Application.created_at <= date.replace(hour=23, minute=59, second=59)
        ).count()
        application_data.append(count)
    

    pending_count = Application.query.filter_by(status='Pending').count()
    reviewed_count = Application.query.filter_by(status='Reviewed').count()
    rejected_count = Application.query.filter_by(status='Rejected').count()
    
    status_data = [pending_count, reviewed_count, rejected_count, accepted_count]

    recent_jobs = Job.query.order_by(Job.created_at.desc()).limit(5).all()
    
    return render_template(
        'admin/dashboard.html',
        job_count=job_count,
        user_count=user_count,
        application_count=application_count,
        accepted_count=accepted_count,
        application_data=json.dumps(application_data),
        status_data=json.dumps(status_data),
        recent_jobs=recent_jobs
    )

@admin_bp.route('/jobs')
@login_required
def manage_jobs():
    """Manage jobs"""
    if not current_user.is_admin():
        flash('Access denied. Admin privileges required.')
        return redirect(url_for('main.index'))
    
    jobs = Job.query.order_by(Job.created_at.desc()).all()
    return render_template('admin/jobs.html', jobs=jobs)

@admin_bp.route('/jobs/create', methods=['GET', 'POST'])
@login_required
def create_job():
    """Create a new job posting"""
    if not current_user.is_admin():
        flash('Access denied. Admin privileges required.')
        return redirect(url_for('main.index'))
    
    form = JobForm()
    if form.validate_on_submit():
        job = Job(
            title=form.title.data,
            description=form.description.data,
            requirements=form.requirements.data,
            location=form.location.data,
            salary=form.salary.data,
            contact_info=form.contact_info.data,
            posted_by=current_user.id
        )
        db.session.add(job)
        db.session.commit()
        flash('Job posted successfully!')
        return redirect(url_for('admin.manage_jobs'))
    
    return render_template('admin/create_job.html', form=form)

@admin_bp.route('/jobs/edit/<int:job_id>', methods=['GET', 'POST'])
@login_required
def edit_job(job_id):
    """Edit a job posting"""
    if not current_user.is_admin():
        flash('Access denied. Admin privileges required.')
        return redirect(url_for('main.index'))
    
    job = Job.query.get_or_404(job_id)
    form = JobForm()
    
    if form.validate_on_submit():
        job.title = form.title.data
        job.description = form.description.data
        job.requirements = form.requirements.data
        job.location = form.location.data
        job.salary = form.salary.data
        job.contact_info = form.contact_info.data
        db.session.commit()
        flash('Job updated successfully!')
        return redirect(url_for('admin.manage_jobs'))
    
    if request.method == 'GET':
        form.title.data = job.title
        form.description.data = job.description
        form.requirements.data = job.requirements
        form.location.data = job.location
        form.salary.data = job.salary
        form.contact_info.data = job.contact_info
    
    return render_template('admin/edit_job.html', form=form, job=job)

@admin_bp.route('/jobs/delete/<int:job_id>', methods=['POST'])
@login_required
def delete_job(job_id):
    """Delete a job posting"""
    if not current_user.is_admin():
        flash('Access denied. Admin privileges required.')
        return redirect(url_for('main.index'))
    
    job = Job.query.get_or_404(job_id)
    
    # Delete all applications for this job
    Application.query.filter_by(job_id=job_id).delete()
    
    db.session.delete(job)
    db.session.commit()
    flash('Job deleted successfully!')
    return redirect(url_for('admin.manage_jobs'))

@admin_bp.route('/applications')
@login_required
def manage_applications():
    """View and manage job applications"""
    if not current_user.is_admin():
        flash('Access denied. Admin privileges required.')
        return redirect(url_for('main.index'))
    
    applications = Application.query.order_by(Application.created_at.desc()).all()
    return render_template('admin/applications.html', applications=applications)

@admin_bp.route('/applications/update/<int:application_id>', methods=['POST'])
@login_required
def update_application_status(application_id):
    """Update application status"""
    if not current_user.is_admin():
        flash('Access denied. Admin privileges required.')
        return redirect(url_for('main.index'))
    
    application = Application.query.get_or_404(application_id)
    status = request.form.get('status')
    
    if status in ['Pending', 'Reviewed', 'Rejected', 'Accepted']:
        application.status = status
        application.updated_at = datetime.utcnow()
        db.session.commit()
        flash('Application status updated!')
    
    return redirect(url_for('admin.manage_applications'))

@admin_bp.route('/users')
@login_required
def manage_users():
    """Manage users"""
    if not current_user.is_admin():
        flash('Access denied. Admin privileges required.')
        return redirect(url_for('main.index'))
    
    from app.models import Application
    
    page = request.args.get('page', 1, type=int)
    per_page = 10

    search_query = request.args.get('search', '')
    if search_query:
        users = User.query.filter(
            or_(
                User.username.ilike(f'%{search_query}%'),
                User.email.ilike(f'%{search_query}%')
            )
        ).order_by(User.created_at.desc())
    else:
        users = User.query.order_by(User.created_at.desc())
    
    pagination = users.paginate(page=page, per_page=per_page)
    users = pagination.items
    
    return render_template('admin/users.html', users=users, pagination=pagination, Application=Application)

@admin_bp.route('/users/delete/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    """Delete a user"""
    if not current_user.is_admin():
        flash('Access denied. Admin privileges required.')
        return redirect(url_for('main.index'))
    
    user = User.query.get_or_404(user_id)

    if user.id == current_user.id:
        flash('You cannot delete yourself.')
        return redirect(url_for('admin.manage_users'))

    Application.query.filter_by(user_id=user_id).delete()

    Resume.query.filter_by(user_id=user_id).delete()

    db.session.delete(user)
    db.session.commit()
    
    flash(f'User {user.username} has been deleted. ')
    return redirect(url_for('admin.manage_users'))

@admin_bp.route('/users/toggle-role/<int:user_id>', methods=['POST'])
@login_required
def toggle_role(user_id):
    """Toggle user role between user and admin"""
    if not current_user.is_admin():
        flash('Access denied. Admin privileges required.')
        return redirect(url_for('main.index'))
    
    user = User.query.get_or_404(user_id)

    if user.id == current_user.id:
        flash('You cannot change your own role.')
        return redirect(url_for('admin.manage_users'))
    
    if user.role == Role.USER:
        user.role = Role.ADMIN
        flash(f'User {user.username} has been promoted to admin.')
    else:
        user.role = Role.USER
        flash(f'Admin {user.username} has been demoted to user.')
    
    db.session.commit()
    return redirect(url_for('admin.manage_users'))

@admin_bp.route('/user/<int:user_id>/applications')
@login_required
def user_applications(user_id):
    """API endpoint to get a user's applications"""
    if not current_user.is_admin():
        return jsonify({'error': 'Unauthorized access'}), 403
    
    user = User.query.get_or_404(user_id)
    applications = []
    
    for app in user.applications.order_by(Application.created_at.desc()).limit(5).all():
        job = Job.query.get(app.job_id)
        if job:
            applications.append({
                'id': app.id,
                'job_id': app.job_id,
                'job_title': job.title,
                'status': app.status,
                'created_at': app.created_at.strftime('%Y-%m-%d')
            })
    
    return jsonify({
        'user_id': user.id,
        'applications': applications
    }) 