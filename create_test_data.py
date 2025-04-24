from app import create_app, db
from app.models import User, Job, Resume, Application, Role
from datetime import datetime, timedelta
import random

app = create_app()

def create_test_data():
    with app.app_context():
        admin = User(
            username='admin',
            email='admin@example.com',
            password='adminpass',
            role=Role.ADMIN
        )
        db.session.add(admin)

        users = []
        for i in range(1, 6):
            user = User(
                username=f'user{i}',
                email=f'user{i}@example.com',
                password=f'password{i}'
            )
            users.append(user)
            db.session.add(user)
        
        db.session.commit()
        print("Created admin and 5 regular users.")
        

        job_titles = [
            "Software Engineer", "Web Developer", "Data Analyst", 
            "Product Manager", "UI/UX Designer", "Marketing Specialist",
            "Sales Representative", "Customer Support", "HR Manager",
            "Finance Analyst"
        ]
        
        job_locations = ["Hong Kong", "Kowloon", "New Territories", "Shenzhen", "Remote"]
        
        job_salaries = [
            "HK$15,000 - HK$20,000", 
            "HK$20,000 - HK$25,000",
            "HK$25,000 - HK$30,000", 
            "HK$30,000 - HK$40,000",
            "HK$40,000 - HK$50,000"
        ]
        
        jobs = []
        for i in range(10):
            job = Job(
                title=job_titles[i],
                description=f"This is a detailed description for the {job_titles[i]} position. We are looking for motivated professionals who want to grow with our company.",
                requirements=f"Requirements for {job_titles[i]}:\n- Relevant experience\n- Good communication skills\n- Team player\n- Problem-solving abilities",
                location=random.choice(job_locations),
                salary=random.choice(job_salaries),
                contact_info=f"HR Department, Email: hr@company{i+1}.com",
                posted_by=admin.id,
                created_at=datetime.utcnow() - timedelta(days=random.randint(1, 30))
            )
            jobs.append(job)
            db.session.add(job)
            
        db.session.commit()
        print("Created 10 job postings.")

        education_levels = ["High School", "Associate's Degree", "Bachelor's Degree", "Master's Degree", "PhD"]
        
        for user in users:
            resume = Resume(
                user_id=user.id,
                name=f"{user.username.capitalize()} User",
                gender=random.choice(["Male", "Female"]),
                age=random.randint(22, 45),
                education=random.choice(education_levels),
                contact=f"Phone: +852 {random.randint(10000000, 99999999)}, Email: {user.email}",
                experience=f"Work Experience:\n- Company A: 2 years\n- Company B: 3 years\n- Various projects and internships",
                introduction=f"I am a motivated professional with experience in various fields. I am looking for new opportunities to grow and develop my skills."
            )
            db.session.add(resume)
            
        db.session.commit()
        print("Created resumes for all regular users.")
        

        statuses = ["Pending", "Reviewed", "Rejected", "Accepted"]
        
        for user in users:
            user_resume = Resume.query.filter_by(user_id=user.id).first()
            job_count = random.randint(2, 4)
            selected_jobs = random.sample(jobs, job_count)
            
            for job in selected_jobs:
                application = Application(
                    user_id=user.id,
                    job_id=job.id,
                    resume_id=user_resume.id,
                    status=random.choice(statuses),
                    created_at=datetime.utcnow() - timedelta(days=random.randint(1, 20))
                )
                db.session.add(application)
                
        db.session.commit()
        print("Created job applications for users.")
        
        print("Test data creation completed successfully!")

if __name__ == '__main__':
    create_test_data() 