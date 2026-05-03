# 🚀 AVIGHNA Deployment Guide

## Prerequisites

Before deploying, ensure you have:
- GitHub account
- Vercel account (for frontend)
- Render/Railway account (for backend)
- Neon/Supabase account (for PostgreSQL database)

---

## 📦 Step 1: Prepare Repository

### 1.1 Clean Up (if not done already)

```bash
# Delete unnecessary files
rm ARCHITECTURE_CHANGES.md AVIGHNA_HONEST_ASSESSMENT.md CURRENT_STATUS.md \
   FINAL_STATUS.md FIX_MANUAL_REGISTRATION.md IMPLEMENTATION_SUMMARY.md \
   MANUAL_REGISTRATION_AUDIT.md MANUAL_REGISTRATION_FIX_SUMMARY.md \
   MANUAL_REGISTRATION_IMPLEMENTATION.md NEXT_STEPS.md QUICK_TEST_REFERENCE.md \
   ROUTER_DISCOVERY_BLOCKED.md ROUTER_DISCOVERY_IMPLEMENTATION.md \
   TERMUX_ATTACK_SIMULATION.md TERMUX_TEST_GUIDE.md \
   check_db.py list_routes.py test_manual_registration.py test_router_discovery.py \
   backend.log avighna_defense.db dome.code-workspace \
   restart_backend.bat start_backend.bat .env.template

rm -rf logs/
```

### 1.2 Push to GitHub

```bash
git add .
git commit -m "Prepare for deployment"
git push origin main
```

---

## 🗄️ Step 2: Deploy PostgreSQL Database

### Option A: Neon (Recommended - Free Tier)

1. Go to https://neon.tech
2. Sign up / Log in
3. Create new project: "avighna-defense"
4. Copy connection string (looks like):
   ```
   postgresql://user:password@ep-xxx.neon.tech/avighna_defense
   ```
5. Save this for later

### Option B: Supabase

1. Go to https://supabase.com
2. Create new project: "avighna-defense"
3. Go to Settings → Database
4. Copy connection string (Pooler mode)
5. Save this for later

### Option C: Railway

1. Go to https://railway.app
2. New Project → Provision PostgreSQL
3. Copy DATABASE_URL from Variables tab
4. Save this for later

---

## 🖥️ Step 3: Deploy Backend

### Option A: Render (Recommended)

1. Go to https://render.com
2. New → Web Service
3. Connect your GitHub repository
4. Configure:
   - **Name**: `avighna-backend`
   - **Environment**: `Python 3`
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `uvicorn backend.main:app --host 0.0.0.0 --port $PORT`
   - **Plan**: Free

5. Add Environment Variables:
   ```
   DATABASE_URL=<your-neon-connection-string>
   SECRET_KEY=<generate-random-32-char-string>
   ALGORITHM=HS256
   ACCESS_TOKEN_EXPIRE_MINUTES=480
   FRONTEND_URL=<will-add-after-frontend-deploy>
   ```

6. Click "Create Web Service"
7. Wait for deployment (5-10 minutes)
8. Copy your backend URL: `https://avighna-backend.onrender.com`

### Option B: Railway

1. Go to https://railway.app
2. New Project → Deploy from GitHub repo
3. Select your repository
4. Add Environment Variables (same as above)
5. Railway will auto-detect Python and deploy
6. Copy your backend URL from Settings

---

## 🌐 Step 4: Deploy Frontend

### Vercel (Recommended)

1. Go to https://vercel.com
2. Import Project → Select your GitHub repository
3. Configure:
   - **Framework Preset**: Next.js
   - **Root Directory**: `frontend`
   - **Build Command**: `npm run build`
   - **Output Directory**: `.next`

4. Add Environment Variable:
   ```
   NEXT_PUBLIC_API_URL=<your-backend-url-from-step-3>
   ```
   Example: `https://avighna-backend.onrender.com`

5. Click "Deploy"
6. Wait for deployment (2-5 minutes)
7. Copy your frontend URL: `https://avighna-defense.vercel.app`

---

## 🔗 Step 5: Connect Everything

### 5.1 Update Backend CORS

Go back to your backend deployment (Render/Railway):

1. Add/Update environment variable:
   ```
   FRONTEND_URL=<your-vercel-url>
   ```
   Example: `https://avighna-defense.vercel.app`

2. Redeploy backend (it will restart automatically)

### 5.2 Verify Database Connection

Your backend should automatically connect to PostgreSQL on startup.

Check backend logs for:
```
INFO: Database initialized successfully
INFO: Using PostgreSQL database
```

---

## ✅ Step 6: Test Deployment

### 6.1 Test Backend

Visit: `https://your-backend-url.onrender.com/docs`

You should see FastAPI Swagger documentation.

Test endpoints:
- `GET /health` - Should return `{"status": "healthy"}`
- `GET /` - Should return API info

### 6.2 Test Frontend

Visit: `https://your-app.vercel.app`

You should see:
1. Login page
2. Able to signup
3. Able to login
4. Dashboard loads

### 6.3 Test Full Flow

1. **Signup**: Create new account
2. **Login**: Login with credentials
3. **Dashboard**: Should load with cards
4. **Devices**: Navigate to devices (via dashboard card)
5. **Register Device**: Try manual registration
6. **Reports**: Check reports page
7. **Settings**: Check settings page
8. **Profile**: Check profile page
9. **FOX**: Check threat intelligence page

---

## 🐛 Troubleshooting

### Backend Issues

**Problem**: Backend won't start
- Check logs in Render/Railway dashboard
- Verify DATABASE_URL is correct
- Verify all required packages in requirements.txt

**Problem**: Database connection fails
- Check DATABASE_URL format
- Ensure database exists
- Check database credentials

**Problem**: CORS errors
- Verify FRONTEND_URL is set correctly
- Check backend logs for CORS configuration
- Ensure frontend URL matches exactly (no trailing slash)

### Frontend Issues

**Problem**: Can't connect to backend
- Verify NEXT_PUBLIC_API_URL is set
- Check if backend is running
- Test backend URL directly in browser

**Problem**: Build fails
- Check Vercel build logs
- Verify all dependencies in package.json
- Check for TypeScript errors

### Database Issues

**Problem**: Tables don't exist
- Backend creates tables automatically on first run
- Check backend logs for "Database initialized"
- Verify DATABASE_URL points to correct database

---

## 🔒 Security Checklist

Before going live:

- [ ] Changed SECRET_KEY from default
- [ ] Using PostgreSQL (not SQLite)
- [ ] CORS configured with actual frontend URL
- [ ] No API keys in code
- [ ] .env file not committed
- [ ] Database credentials secure
- [ ] HTTPS enabled (automatic on Vercel/Render)

---

## 📊 Monitoring

### Backend Health

Check: `https://your-backend-url/health`

Should return: `{"status": "healthy"}`

### Frontend Health

Visit your Vercel URL - should load without errors

### Database Health

Check Neon/Supabase dashboard for:
- Connection count
- Query performance
- Storage usage

---

## 🎯 Post-Deployment

### Update README

Add deployment URLs to README.md:

```markdown
## 🌐 Live Demo

- **Frontend**: https://avighna-defense.vercel.app
- **Backend API**: https://avighna-backend.onrender.com
- **API Docs**: https://avighna-backend.onrender.com/docs
```

### Monitor Logs

- **Vercel**: Check deployment logs and runtime logs
- **Render**: Check logs tab for backend errors
- **Neon**: Monitor database queries

---

## 💰 Cost Breakdown

### Free Tier Limits

**Vercel (Frontend)**:
- ✅ Unlimited deployments
- ✅ 100GB bandwidth/month
- ✅ Automatic HTTPS
- ✅ Custom domains

**Render (Backend)**:
- ✅ 750 hours/month free
- ⚠️ Spins down after 15min inactivity
- ⚠️ Cold start ~30 seconds
- ✅ Automatic HTTPS

**Neon (Database)**:
- ✅ 3GB storage
- ✅ 1 project
- ✅ Automatic backups
- ✅ Serverless PostgreSQL

**Total Cost**: $0/month (Free tier)

---

## 🚀 Upgrade Path

When you need more:

1. **Render**: Upgrade to $7/month for always-on
2. **Neon**: Upgrade to $19/month for more storage
3. **Vercel**: Pro plan $20/month for team features

---

## 📞 Support

If you encounter issues:

1. Check deployment logs
2. Review this guide
3. Check GitHub Issues
4. Open new issue with:
   - Platform (Vercel/Render/Neon)
   - Error message
   - Steps to reproduce

---

**Deployment complete! Your AVIGHNA instance is now live! 🎉**
