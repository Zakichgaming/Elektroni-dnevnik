// База данных в localStorage
const database = {
    users: JSON.parse(localStorage.getItem('users')) || [],
    schedule: JSON.parse(localStorage.getItem('schedule')) || [],
    journal: JSON.parse(localStorage.getItem('journal')) || [],
    
    saveUsers: function() {
        localStorage.setItem('users', JSON.stringify(this.users));
    },
    
    saveSchedule: function() {
        localStorage.setItem('schedule', JSON.stringify(this.schedule));
    },
    
    saveJournal: function() {
        localStorage.setItem('journal', JSON.stringify(this.journal));
    },
    
    // Инициализация тестовых данных
    init: function() {
        if (this.users.length === 0) {
            // Тестовый учитель
            this.users.push({
                id: 1,
                fullName: "Иванова Мария Петровна",
                email: "teacher@school.ru",
                class: "5А",
                role: "teacher",
                password: "teacher123",
                childId: null
            });
            
            // Тестовый ученик
            this.users.push({
                id: 2,
                fullName: "Петров Иван Сергеевич",
                email: "student@school.ru",
                class: "5А",
                role: "student",
                password: "student123",
                childId: null
            });
            
            // Тестовый родитель
            this.users.push({
                id: 3,
                fullName: "Петрова Ольга Ивановна",
                email: "parent@school.ru",
                class: "5А",
                role: "parent",
                password: "parent123",
                childId: 2
            });
            
            this.saveUsers();
        }
        
        if (this.schedule.length === 0) {
            const days = ["Понедельник", "Вторник", "Среда", "Четверг", "Пятница"];
            const subjects = ["Математика", "Русский язык", "Литература", "История", "Биология", "География"];
            
            days.forEach(day => {
                for (let i = 0; i < 6; i++) {
                    this.schedule.push({
                        id: this.schedule.length + 1,
                        class: "5А",
                        day: day,
                        subject: subjects[Math.floor(Math.random() * subjects.length)],
                        time: `${8 + i}:00 - ${8 + i + 1}:00`,
                        room: `${200 + Math.floor(Math.random() * 100)}`
                    });
                }
            });
            
            this.saveSchedule();
        }
        
        if (this.journal.length === 0) {
            const dates = ["2023-09-01", "2023-09-02", "2023-09-05", "2023-09-06", "2023-09-07"];
            const subjects = ["Математика", "Русский язык", "Литература", "История", "Биология"];
            
            dates.forEach(date => {
                subjects.forEach(subject => {
                    this.journal.push({
                        id: this.journal.length + 1,
                        studentId: 2,
                        date: date,
                        subject: subject,
                        attendance: Math.random() > 0.2,
                        grade: Math.random() > 0.3 ? Math.floor(Math.random() * 4) + 2 : null,
                        homework: "Подготовить доклад по теме урока",
                        teacherNotes: ""
                    });
                });
            });
            
            this.saveJournal();
        }
    }
};

// Текущий пользователь
let currentUser = null;

// Инициализация при загрузке
window.onload = function() {
    database.init();
    showPage('login');
    
    // Проверяем, есть ли сохраненный пользователь
    const savedUser = localStorage.getItem('currentUser');
    if (savedUser) {
        currentUser = JSON.parse(savedUser);
        updateUI();
        showPage('dashboard');
    }
};

// Показать страницу
function showPage(pageId) {
    document.querySelectorAll('.page').forEach(page => {
        page.classList.add('hidden');
    });
    
    document.getElementById(`${pageId}-page`).classList.remove('hidden');
    
    // Загружаем контент для страницы
    switch(pageId) {
        case 'dashboard':
            loadDashboard();
            break;
        case 'schedule':
            loadSchedule();
            break;
        case 'journal':
            loadJournal();
            break;
    }
}

// Обновление интерфейса
function updateUI() {
    const authButtons = document.getElementById('auth-buttons');
    const userInfo = document.getElementById('user-info');
    const journalLink = document.getElementById('journal-link');
    
    if (currentUser) {
        authButtons.classList.add('hidden');
        userInfo.classList.remove('hidden');
        document.getElementById('user-name-role').textContent = 
            `${currentUser.fullName} (${getRoleName(currentUser.role)})`;
        
        // Показываем журнал только учителям
        if (currentUser.role === 'teacher') {
            journalLink.classList.remove('hidden');
        } else {
            journalLink.classList.add('hidden');
        }
    } else {
        authButtons.classList.remove('hidden');
        userInfo.classList.add('hidden');
        journalLink.classList.add('hidden');
    }
}

// Получить название роли
function getRoleName(role) {
    switch(role) {
        case 'teacher': return 'Учитель';
        case 'student': return 'Ученик';
        case 'parent': return 'Родитель';
        default: return role;
    }
}

// Показать сообщение
function showAlert(message, type) {
    const alerts = document.getElementById('alerts');
    const alert = document.createElement('div');
    alert.className = `alert alert-${type}`;
    alert.textContent = message;
    alerts.appendChild(alert);
    
    setTimeout(() => {
        alert.remove();
    }, 3000);
}

// Вход
function login(event) {
    event.preventDefault();
    
    const email = document.getElementById('login-email').value;
    const password = document.getElementById('login-password').value;
    
    const user = database.users.find(u => u.email === email && u.password === password);
    
    if (user) {
        currentUser = user;
        localStorage.setItem('currentUser', JSON.stringify(user));
        updateUI();
        showPage('dashboard');
        showAlert('Вход выполнен успешно!', 'success');
    } else {
        showAlert('Неверный email или пароль', 'error');
    }
}

// Регистрация
function register(event) {
    event.preventDefault();
    
    const fullName = document.getElementById('reg-fullname').value;
    const email = document.getElementById('reg-email').value;
    const class_ = document.getElementById('reg-class').value;
    const role = document.getElementById('reg-role').value;
    const password = document.getElementById('reg-password').value;
    const confirmPassword = document.getElementById('reg-confirm-password').value;
    
    // Проверки
    if (password !== confirmPassword) {
        showAlert('Пароли не совпадают', 'error');
        return;
    }
    
    if (database.users.some(u => u.email === email)) {
        showAlert('Пользователь с таким email уже существует', 'error');
        return;
    }
    
    let childId = null;
    if (role === 'parent') {
        const childName = document.getElementById('reg-child').value;
        const child = database.users.find(u => u.fullName === childName && u.class === class_);
        
        if (!child) {
            showAlert('Ученик не найден. Проверьте ФИО и класс.', 'error');
            return;
        }
        
        childId = child.id;
    }
    
    // Создаем нового пользователя
    const newUser = {
        id: database.users.length > 0 ? Math.max(...database.users.map(u => u.id)) + 1 : 1,
        fullName: fullName,
        email: email,
        class: class_,
        role: role,
        password: password,
        childId: childId
    };
    
    database.users.push(newUser);
    database.saveUsers();
    
    showAlert('Регистрация успешна! Теперь вы можете войти.', 'success');
    showPage('login');
}

// Выход
function logout() {
    currentUser = null;
    localStorage.removeItem('currentUser');
    updateUI();
    showPage('login');
    showAlert('Вы успешно вышли из системы', 'success');
}

// Показать/скрыть поле для ребенка
function toggleChildField() {
    const role = document.getElementById('reg-role').value;
    const childField = document.getElementById('child-field');
    
    childField.classList.toggle('hidden', role !== 'parent');
}

// Загрузка главной страницы
function loadDashboard() {
    const content = document.getElementById('dashboard-content');
    
    if (currentUser.role === 'teacher') {
        // Для учителя - список учеников
        const students = database.users.filter(u => u.class === currentUser.class && u.role === 'student');
        
        let html = `<h3>Ученики класса ${currentUser.class}</h3>`;
        html += '<ul>';
        students.forEach(student => {
            html += `<li>${student.fullName}</li>`;
        });
        html += '</ul>';
        
        content.innerHTML = html;
    } else if (currentUser.role === 'parent') {
        // Для родителя - информация о ребенке
        const child = database.users.find(u => u.id === currentUser.childId);
        
        if (child) {
            const journalEntries = database.journal
                .filter(j => j.studentId === child.id)
                .sort((a, b) => new Date(b.date) - new Date(a.date))
                .slice(0, 5);
            
            let html = `
                <h3>Информация о вашем ребенке</h3>
                <p><strong>ФИО:</strong> ${child.fullName}</p>
                <p><strong>Класс:</strong> ${child.class}</p>
                
                <h4>Последние оценки</h4>
                <table>
                    <thead>
                        <tr>
                            <th>Дата</th>
                            <th>Предмет</th>
                            <th>Посещаемость</th>
                            <th>Оценка</th>
                            <th>Домашнее задание</th>
                        </tr>
                    </thead>
                    <tbody>
            `;
            
            journalEntries.forEach(entry => {
                html += `
                    <tr>
                        <td>${entry.date}</td>
                        <td>${entry.subject}</td>
                        <td>
                            <span class="badge ${entry.attendance ? 'badge-present' : 'badge-absent'}">
                                ${entry.attendance ? 'Присутствовал' : 'Отсутствовал'}
                            </span>
                        </td>
                        <td>
                            ${entry.grade ? 
                                `<span class="grade grade-${entry.grade}">${entry.grade}</span>` : 
                                'Нет оценки'}
                        </td>
                        <td>${entry.homework}</td>
                    </tr>
                `;
            });
            
            html += `
                    </tbody>
                </table>
            `;
            
            content.innerHTML = html;
        } else {
            content.innerHTML = '<p>Информация о ребенке не найдена</p>';
        }
    } else {
        // Для ученика - его оценки
        const journalEntries = database.journal
            .filter(j => j.studentId === currentUser.id)
            .sort((a, b) => new Date(b.date) - new Date(a.date))
            .slice(0, 5);
        
        let html = `
            <h3>Ваши последние оценки</h3>
            <table>
                <thead>
                    <tr>
                        <th>Дата</th>
                        <th>Предмет</th>
                        <th>Посещаемость</th>
                        <th>Оценка</th>
                        <th>Домашнее задание</th>
                    </tr>
                </thead>
                <tbody>
        `;
        
        journalEntries.forEach(entry => {
            html += `
                <tr>
                    <td>${entry.date}</td>
                    <td>${entry.subject}</td>
                    <td>
                        <span class="badge ${entry.attendance ? 'badge-present' : 'badge-absent'}">
                            ${entry.attendance ? 'Присутствовал' : 'Отсутствовал'}
                        </span>
                    </td>
                    <td>
                        ${entry.grade ? 
                            `<span class="grade grade-${entry.grade}">${entry.grade}</span>` : 
                            'Нет оценки'}
                    </td>
                    <td>${entry.homework}</td>
                </tr>
            `;
        });
        
        html += `
                </tbody>
            </table>
        `;
        
        content.innerHTML = html;
    }
}

// Загрузка расписания
function loadSchedule() {
    const content = document.getElementById('schedule-content');
    const classSchedule = database.schedule.filter(s => s.class === currentUser.class);
    
    const days = {};
    classSchedule.forEach(item => {
        if (!days[item.day]) {
            days[item.day] = [];
        }
        days[item.day].push(item);
    });
    
    let html = '';
    
    // Форма добавления расписания (только для учителей)
    if (currentUser.role === 'teacher') {
        html += `
            <div class="manage-schedule">
                <h3>Управление расписанием</h3>
                <form onsubmit="addScheduleItem(event)">
                    <div class="form-group">
                        <label for="schedule-day">День недели:</label>
                        <select id="schedule-day" required>
                            <option value="Понедельник">Понедельник</option>
                            <option value="Вторник">Вторник</option>
                            <option value="Среда">Среда</option>
                            <option value="Четверг">Четверг</option>
                            <option value="Пятница">Пятница</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label for="schedule-time">Время:</label>
                        <input type="text" id="schedule-time" placeholder="08:30-09:15" required>
                    </div>
                    <div class="form-group">
                        <label for="schedule-subject">Предмет:</label>
                        <input type="text" id="schedule-subject" required>
                    </div>
                    <div class="form-group">
                        <label for="schedule-room">Кабинет:</label>
                        <input type="text" id="schedule-room" required>
                    </div>
                    <button type="submit" class="btn">Добавить в расписание</button>
                </form>
            </div>
        `;
    }
    
    html += '<h3>Расписание занятий</h3>';
    
    if (Object.keys(days).length === 0) {
        html += '<p>Расписание не найдено</p>';
    } else {
        for (const day in days) {
            html += `
                <div class="schedule-day">
                    <h4>${day}</h4>
                    <table class="schedule-table">
                        <thead>
                            <tr>
                                <th>Время</th>
                                <th>Предмет</th>
                                <th>Кабинет</th>
                                ${currentUser.role === 'teacher' ? '<th>Действия</th>' : ''}
                            </tr>
                        </thead>
                        <tbody>
            `;
            
            days[day].forEach(lesson => {
                html += `
                    <tr>
                        <td>${lesson.time}</td>
                        <td>${lesson.subject}</td>
                        <td>${lesson.room}</td>
                        ${currentUser.role === 'teacher' ? 
                          `<td><button onclick="removeScheduleItem(${lesson.id})" class="btn btn-logout">Удалить</button></td>` : ''}
                    </tr>
                `;
            });
            
            html += `
                        </tbody>
                    </table>
                </div>
            `;
        }
    }
    
    content.innerHTML = html;
}

// Добавление пункта расписания
function addScheduleItem(event) {
    event.preventDefault();
    
    if (currentUser.role !== 'teacher') {
        showAlert('Только учителя могут редактировать расписание', 'error');
        return;
    }

    const day = document.getElementById('schedule-day').value;
    const time = document.getElementById('schedule-time').value;
    const subject = document.getElementById('schedule-subject').value;
    const room = document.getElementById('schedule-room').value;

    const newItem = {
        id: database.schedule.length > 0 ? Math.max(...database.schedule.map(i => i.id)) + 1 : 1,
        class: currentUser.class,
        day: day,
        time: time,
        subject: subject,
        room: room
    };

    database.schedule.push(newItem);
    database.saveSchedule();
    
    showAlert('Пункт расписания добавлен', 'success');
    loadSchedule(); // Перезагружаем расписание
    
    // Очищаем форму
    document.getElementById('schedule-time').value = '';
    document.getElementById('schedule-subject').value = '';
    document.getElementById('schedule-room').value = '';
}

// Удаление пункта расписания
function removeScheduleItem(id) {
    if (currentUser.role !== 'teacher') {
        showAlert('Только учителя могут редактировать расписание', 'error');
        return;
    }
    
    const index = database.schedule.findIndex(item => item.id === id);
    if (index !== -1) {
        database.schedule.splice(index, 1);
        database.saveSchedule();
        showAlert('Пункт расписания удален', 'success');
        loadSchedule();
    }
}

// Загрузка журнала (для учителей)
function loadJournal() {
    const content = document.getElementById('journal-content');
    
    if (currentUser.role !== 'teacher') {
        content.innerHTML = '<p>Доступ запрещен</p>';
        return;
    }

    const students = database.users.filter(u => u.class === currentUser.class && u.role === 'student');
    const journalEntries = database.journal
        .filter(j => {
            const student = database.users.find(u => u.id === j.studentId);
            return student && student.class === currentUser.class;
        })
        .sort((a, b) => new Date(b.date) - new Date(a.date));
    
    let html = `
        <div class="manage-students">
            <h3>Управление учениками</h3>
            <form onsubmit="addStudent(event)">
                <div class="form-group">
                    <label for="new-student-name">ФИО ученика:</label>
                    <input type="text" id="new-student-name" required>
                </div>
                <div class="form-group">
                    <label for="new-student-email">Email:</label>
                    <input type="email" id="new-student-email" required>
                </div>
                <div class="form-group">
                    <label for="new-student-password">Пароль:</label>
                    <input type="password" id="new-student-password" required>
                </div>
                <button type="submit" class="btn">Добавить ученика</button>
            </form>

            <h4>Список учеников класса</h4>
            <ul id="students-list">
    `;
    
    students.forEach(student => {
        html += `<li>${student.fullName} (${student.email})</li>`;
    });
    
    html += `
            </ul>
        </div>

        <h3>Добавить запись в журнал</h3>
        <form onsubmit="addJournalEntry(event)">
            <div class="form-group">
                <label for="journal-student">Ученик:</label>
                <select id="journal-student" required>
                    ${students.map(s => `<option value="${s.id}">${s.fullName}</option>`).join('')}
                </select>
            </div>
            
            <div class="form-group">
                <label for="journal-date">Дата:</label>
                <input type="date" id="journal-date" required>
            </div>
            
            <div class="form-group">
                <label for="journal-subject">Предмет:</label>
                <input type="text" id="journal-subject" required>
            </div>
            
            <div class="form-group">
                <label>
                    <input type="checkbox" id="journal-attendance" checked>
                    Присутствовал
                </label>
            </div>
            
            <div class="form-group">
                <label for="journal-grade">Оценка (2-5):</label>
                <input type="number" id="journal-grade" min="2" max="5">
            </div>
            
            <div class="form-group">
                <label for="journal-homework">Домашнее задание:</label>
                <textarea id="journal-homework"></textarea>
            </div>
            
            <div class="form-group">
                <label for="journal-notes">Заметки учителя:</label>
                <textarea id="journal-notes"></textarea>
            </div>
            
            <button type="submit" class="btn">Добавить запись</button>
        </form>
        
        <h3 style="margin-top: 30px;">Последние записи</h3>
        <table>
            <thead>
                <tr>
                    <th>Дата</th>
                    <th>Ученик</th>
                    <th>Предмет</th>
                    <th>Посещаемость</th>
                    <th>Оценка</th>
                    <th>Домашнее задание</th>
                    <th>Действия</th>
                </tr>
            </thead>
            <tbody>
    `;
    
    journalEntries.slice(0, 10).forEach(entry => {
        const student = database.users.find(u => u.id === entry.studentId);
        html += `
            <tr>
                <td>${entry.date}</td>
                <td>${student ? student.fullName : 'Неизвестно'}</td>
                <td>${entry.subject}</td>
                <td>
                    <span class="badge ${entry.attendance ? 'badge-present' : 'badge-absent'}">
                        ${entry.attendance ? 'Присутствовал' : 'Отсутствовал'}
                    </span>
                </td>
                <td>
                    ${entry.grade ? 
                        `<span class="grade grade-${entry.grade}">${entry.grade}</span>` : 
                        'Нет оценки'}
                </td>
                <td>${entry.homework}</td>
                <td><button onclick="removeJournalEntry(${entry.id})" class="btn btn-logout">Удалить</button></td>
            </tr>
        `;
    });
    
    html += `
            </tbody>
        </table>
    `;
    
    content.innerHTML = html;
}

// Добавление ученика
function addStudent(event) {
    event.preventDefault();
    
    if (currentUser.role !== 'teacher') {
        showAlert('Только учителя могут добавлять учеников', 'error');
        return;
    }

    const name = document.getElementById('new-student-name').value;
    const email = document.getElementById('new-student-email').value;
    const password = document.getElementById('new-student-password').value;

    // Проверка на существующий email
    if (database.users.some(u => u.email === email)) {
        showAlert('Ученик с таким email уже существует', 'error');
        return;
    }

    const newStudent = {
        id: database.users.length > 0 ? Math.max(...database.users.map(u => u.id)) + 1 : 1,
        fullName: name,
        email: email,
        class: currentUser.class,
        role: 'student',
        password: password,
        childId: null
    };

    database.users.push(newStudent);
    database.saveUsers();
    
    showAlert('Ученик успешно добавлен', 'success');
    loadJournal(); // Перезагружаем журнал с обновленным списком учеников
    document.getElementById('new-student-name').value = '';
    document.getElementById('new-student-email').value = '';
    document.getElementById('new-student-password').value = '';
}

// Добавление записи в журнал
function addJournalEntry(event) {
    event.preventDefault();
    
    const studentId = parseInt(document.getElementById('journal-student').value);
    const date = document.getElementById('journal-date').value;
    const subject = document.getElementById('journal-subject').value;
    const attendance = document.getElementById('journal-attendance').checked;
    const grade = document.getElementById('journal-grade').value;
    const homework = document.getElementById('journal-homework').value;
    const notes = document.getElementById('journal-notes').value;

    const newEntry = {
        id: database.journal.length > 0 ? Math.max(...database.journal.map(j => j.id)) + 1 : 1,
        studentId: studentId,
        date: date,
        subject: subject,
        attendance: attendance,
        grade: grade ? parseInt(grade) : null,
        homework: homework,
        teacherNotes: notes
    };

    database.journal.push(newEntry);
    database.saveJournal();
    
    showAlert('Запись добавлена успешно!', 'success');
    loadJournal();
}

// Удаление записи из журнала
function removeJournalEntry(id) {
    const index = database.journal.findIndex(entry => entry.id === id);
    if (index !== -1) {
        database.journal.splice(index, 1);
        database.saveJournal();
        showAlert('Запись удалена', 'success');
        loadJournal();
    }
}