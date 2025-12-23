# 📺 BuzzTube

BuzzTube is a LAN‑only social hub built with **Flask + SQLite + Bootstrap**.  
It’s designed as a lightweight YouTube/TikTok‑style platform where users can upload videos, share Buzz Shorts, chat, and interact with each other — all running locally on your Raspberry Pi.

---

## 🚀 Features

- **User Accounts**
  - Signup / Login with persistent profiles
  - Premium request system
  - Follows and reports

- **Buzz Shorts**
  - Upload vertical short videos
  - Neon‑styled feed with likes and captions
  - Anti‑spam like system (users can’t like their own shorts or like multiple times)
  - Admin controls to delete shorts

- **Videos**
  - Upload and view longer videos
  - Like and comment system

- **Community**
  - Public chat messages
  - Leaderboard for top users
  - Profile pages with stats

- **Admin Controls**
  - Dedicated admin tabs
  - Manage shorts (delete inappropriate content)
  - Moderate reports and premium requests

---

## 🛠️ Tech Stack

- **Backend:** Flask (Python)
- **Database:** SQLite
- **Frontend:** Bootstrap + custom neon CSS
- **Storage:** Local `static/uploads` folder
- **Platform:** Raspberry Pi (tested on Pi OS)

---

## ⚙️ Setup

Clone the repo and install dependencies:

```bash
git clone https://github.com/<YourUsername>/BuzzTube.git
cd BuzzTube
pip install flask
