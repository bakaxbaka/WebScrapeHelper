# Publishing to GitHub - Quick Start Guide

## 1️⃣ Create GitHub Repository

1. Go to https://github.com/new
2. Create repository: `bitcoin-ecdsa-analyzer`
3. Choose **Public** (to share with others) or **Private** (for personal use)
4. Click **Create repository**

---

## 2️⃣ Configure Git (First Time Only)

```bash
git config --global user.name "Your Name"
git config --global user.email "your.email@github.com"
```

---

## 3️⃣ Push Your Code to GitHub

**Copy your repository URL from GitHub** (green Code button → HTTPS or SSH)

Then run these commands:

```bash
# Initialize git
git init

# Add all files (except those in .gitignore)
git add .

# Create initial commit
git commit -m "Initial commit: Bitcoin ECDSA signature analyzer"

# Add remote repository
git remote add origin https://github.com/YOUR_USERNAME/bitcoin-ecdsa-analyzer.git

# Push to GitHub
git branch -M main
git push -u origin main
```

---

## 🔐 GitHub Authentication

### **Option A: Personal Access Token (Recommended for HTTPS)**
1. GitHub → Settings → Developer settings → Personal access tokens
2. Generate new token with `repo` scope
3. Use token as password when prompted

### **Option B: SSH Key (Most Secure)**
```bash
# Generate SSH key
ssh-keygen -t ed25519 -C "your.email@github.com"

# Add to SSH agent
eval "$(ssh-agent -s)"
ssh-add ~/.ssh/id_ed25519

# Add public key to GitHub (Settings → SSH and GPG keys)
cat ~/.ssh/id_ed25519.pub
```

---

## 📝 Future Updates

After initial setup, update your repository with:

```bash
git add .
git commit -m "Your commit message"
git push
```

---

## 📚 Important Files

- `.gitignore` - Excludes sensitive files (environment variables, secrets)
- `install_requirements.bat` - Windows installation script
- `requirements.txt` - Python package dependencies (for Linux/Mac)

---

## ✅ Verify It Worked

Visit: `https://github.com/YOUR_USERNAME/bitcoin-ecdsa-analyzer`

You should see your code uploaded!

---

## 🆘 Need Help?

- **Cannot connect?** Make sure you have internet and GitHub account
- **Authentication failed?** Check your token/SSH key
- **Git not found?** Install from https://git-scm.com/
