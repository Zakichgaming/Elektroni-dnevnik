from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Модели базы данных
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    class_name = db.Column(db.String(20))
    role = db.Column(db.String(20), nullable=False)  # teacher, student, parent
    password = db.Column(db.String(200), nullable=False)
    child_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    child = db.relationship('User', remote_side=[id])

class Schedule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    class_name = db.Column(db.String(20), nullable=False)
    day_of_week = db.Column(db.String(15), nullable=False)
    subject = db.Column(db.String(50), nullable=False)
    time = db.Column(db.String(20), nullable=False)

class Journal(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    date = db.Column(db.String(10), nullable=False)
    subject = db.Column(db.String(50), nullable=False)
    attendance = db.Column(db.Boolean, default=False)
    grade = db.Column(db.Integer)
    homework = db.Column(db.Text)
    teacher_notes = db.Column(db.Text)

# Декоратор для проверки ролей
def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'role' not in session or session['role'] != role:
                flash('У вас нет доступа к этой странице', 'danger')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Главная страница
@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('login.html')

# Регистрация
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        full_name = request.form['full_name']
        email = request.form['email']
        class_name = request.form['class_name']
        role = request.form['role']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if password != confirm_password:
            flash('Пароли не совпадают', 'danger')
            return redirect(url_for('register'))
        
        if role == 'parent':
            child_name = request.form['child_name']
            child = User.query.filter_by(full_name=child_name, class_name=class_name).first()
            if not child:
                flash('Ученик не найден', 'danger')
                return redirect(url_for('register'))
        else:
            child = None
        
        hashed_password = generate_password_hash(password, method='sha256')
        new_user = User(
            full_name=full_name,
            email=email,
            class_name=class_name,
            role=role,
            password=hashed_password,
            child=child
        )
        
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Регистрация успешна! Теперь вы можете войти.', 'success')
            return redirect(url_for('login'))
        except:
            db.session.rollback()
            flash('Ошибка регистрации. Возможно, email уже используется.', 'danger')
    
    return render_template('register.html')

# Вход
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        user = User.query.filter_by(email=email).first()
        
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['full_name'] = user.full_name
            session['role'] = user.role
            session['class_name'] = user.class_name
            flash('Вход выполнен успешно!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Неверный email или пароль', 'danger')
    
    return render_template('login.html')

# Выход
@app.route('/logout')
def logout():
    session.clear()
    flash('Вы успешно вышли из системы', 'success')
    return redirect(url_for('login'))

# Главная страница после входа
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    
    if user.role == 'teacher':
        students = User.query.filter_by(class_name=user.class_name, role='student').all()
        return render_template('dashboard.html', students=students)
    elif user.role == 'parent':
        child = user.child
        journal_entries = Journal.query.filter_by(student_id=child.id).all() if child else []
        return render_template('dashboard.html', child=child, journal_entries=journal_entries)
    else:  # student
        journal_entries = Journal.query.filter_by(student_id=user.id).all()
        return render_template('dashboard.html', journal_entries=journal_entries)

# Расписание
@app.route('/schedule')
def schedule():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    class_name = session['class_name']
    schedule = Schedule.query.filter_by(class_name=class_name).order_by(Schedule.day_of_week).all()
    
    days = {}
    for item in schedule:
        if item.day_of_week not in days:
            days[item.day_of_week] = []
        days[item.day_of_week].append(item)
    
    return render_template('schedule.html', days=days)

# Журнал (только для учителей)
@app.route('/journal', methods=['GET', 'POST'])
@role_required('teacher')
def journal():
    if request.method == 'POST':
        student_id = request.form['student_id']
        date = request.form['date']
        subject = request.form['subject']
        attendance = 'attendance' in request.form
        grade = request.form.get('grade')
        homework = request.form.get('homework')
        notes = request.form.get('teacher_notes')
        
        new_entry = Journal(
            student_id=student_id,
            date=date,
            subject=subject,
            attendance=attendance,
            grade=int(grade) if grade else None,
            homework=homework,
            teacher_notes=notes
        )
        
        db.session.add(new_entry)
        db.session.commit()
        flash('Запись добавлена успешно!', 'success')
    
    students = User.query.filter_by(class_name=session['class_name'], role='student').all()
    journal_entries = Journal.query.join(User).filter(User.class_name == session['class_name']).all()
    
    return render_template('journal.html', students=students, journal_entries=journal_entries)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)