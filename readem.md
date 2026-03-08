# 🎓 EduGrade AI — Setup Guide

## ⚠️ REQUIREMENT
Node.js version 22 or higher  
Check your version: node --version  
Download: https://nodejs.org

## 📁 FOLDER STRUCTURE (create this exactly)

edugrade-ai/
├── server.js
├── package.json
├── README.md
└── public/
    └── index.html     ← PUT index.html INSIDE this public folder

## 🚀 HOW TO RUN

Open terminal / VS Code terminal inside the edugrade-ai folder:

  node server.js

Then open your browser:  http://localhost:3000

## 👤 USERS

### Teacher
1. Open http://localhost:3000
2. Click Teacher tab → Register → Create account
3. Login → add students in Class List tab
4. Setup assignment + rubric + paste your Anthropic API key
5. Wait for student submissions
6. AI Grade tab → Grade All → results appear
7. Results tab → edit scores → Publish to students

### Student
1. Open http://localhost:3000
2. Click Student tab → Register
3. Enter your roll number (must be added by teacher first)
4. Create a password
5. Login → read assignment → submit answer
6. Check back later → result appears when teacher publishes

## 🔑 API KEY
Get free at: https://console.anthropic.com
Paste in Assignment tab → AI Strictness section

## 💡 NOTES
- No npm install needed! Uses only built-in Node.js modules.
- Database file (edugrade.db) is created automatically on first run.
- Default port is 3000. Change with: PORT=8080 node server.js