# 📺 BuzzTube3  
A LAN‑only social hub built with **Flask + SQLite + Bootstrap**, designed as a lightweight YouTube/TikTok‑style platform for local networks. Users can upload videos, post Buzz Shorts, chat, and interact — all running privately on your own device or Raspberry Pi.

---

## 🚀 Features

### 👤 User Accounts
- Signup / Login with persistent profiles  
- Follow system  
- Report system  
- Premium request system  

### 🎞️ Buzz Shorts
- Upload vertical short videos  
- Neon‑styled feed  
- Like system with anti‑spam protection  
- Users cannot like their own shorts  
- Cannot like multiple times  
- Admin can delete shorts  

### 📹 Full Videos
- Upload and watch longer videos  
- Like + comment system  

### 💬 Community
- Public chat room  
- Leaderboard for top users  
- Profile pages with stats  

### 🛠️ Admin Controls
- Dedicated admin dashboard  
- Manage shorts  
- Moderate reports  
- Handle premium requests  

---

## 🧱 Tech Stack
| Component | Purpose |
|----------|---------|
| **Flask (Python)** | Backend framework |
| **SQLite** | Local database |
| **Bootstrap + Custom CSS** | Frontend UI |
| **Local Storage** | Stores uploads in `static/uploads` |
| **Raspberry Pi** | Fully compatible and tested |

---

## 📁 Project Structure
```
BuzzTube3/
│
├── static/               # CSS, JS, uploads
├── templates/            # HTML templates
│
├── app.py                # Main Flask application
├── init_db.py            # Database initializer
├── buzz.db               # SQLite database
│
├── requirements.txt      # Python dependencies
├── runtime.txt           # Python runtime version
├── Procfile              # For deployment platforms
└── LICENSE               # MIT License
```

---

## ⚙️ Installation & Setup

### 1. Clone the repository
```bash
git clone https://github.com/Mr-A-Hacker/BuzzTube3
cd BuzzTube3
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Initialize the database
```bash
python init_db.py
```

### 4. Run the server
```bash
python app.py
```

### 5. Open in your browser
```
http://localhost:5000
```

---

## 🐳 Optional: Deploy with Docker
*(If you want, I can generate a Dockerfile for you.)*

---

## 📌 Future Improvements
- Dark mode UI  
- Notifications system  
- Direct messaging  
- Better admin analytics  
- Video transcoding for consistent formats  

---

## 🤝 Contributing
Pull requests are welcome!  
Feel free to improve the UI, backend logic, or add new features.

---

## ⭐ Support the Project
If you like this project, consider starring the repo — it helps a lot!
