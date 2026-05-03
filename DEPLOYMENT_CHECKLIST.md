# ✅ AVIGHNA Deployment Checklist

## Pre-Deployment

- [ ] All code committed to GitHub
- [ ] `.env` file NOT in repository (check `.gitignore`)
- [ ] `.env.example` has all required variables
- [ ] No hardcoded secrets in code
- [ ] No API keys in frontend code
- [ ] No database credentials in code
- [ ] Backend uses environment variables for secrets
- [ ] Frontend uses `NEXT_PUBLIC_API_URL` environment variable

## Database Setup

- [ ] PostgreSQL database created (Neon/Supabase/Railway)
- [ ] Database connection string saved securely
- [ ] Database accessible from deployment platform

## Backend Deployment

- [ ] Platform chosen (Render/Railway/Heroku)
- [ ] Repository connected
- [ ] Build command configured: `pip install -r requirements.txt`
- [ ] Start command configured: `uvicorn backend.main:app --host 0.0.0.0 --port $PORT`
- [ ] Environment variables set:
  - [ ] `DATABASE_URL`
  - [ ] `SECRET_KEY` (32+ random characters)
  - [ ] `ALGORITHM=HS256`
  - [ ] `ACCESS_TOKEN_EXPIRE_MINUTES=480`
  - [ ] `FRONTEND_URL` (will add after frontend deploy)
- [ ] Deployment successful
- [ ] Backend URL copied: `https://_____.onrender.com`
- [ ] Health check works: `/health` returns `{"status": "healthy"}`
- [ ] API docs accessible: `/docs` shows Swagger UI

## Frontend Deployment

- [ ] Vercel account created
- [ ] Repository connected
- [ ] Root directory set to: `frontend`
- [ ] Framework preset: Next.js
- [ ] Environment variable set:
  - [ ] `NEXT_PUBLIC_API_URL=<backend-url>`
- [ ] Deployment successful
- [ ] Frontend URL copied: `https://_____.vercel.app`
- [ ] Site loads without errors
- [ ] Login page displays

## Integration

- [ ] Backend CORS updated with frontend URL
- [ ] Backend redeployed with new CORS settings
- [ ] Frontend can connect to backend
- [ ] No CORS errors in browser console

## Testing

### Authentication
- [ ] Can access signup page
- [ ] Can create new account
- [ ] Can login with credentials
- [ ] Token stored in localStorage
- [ ] Redirects to dashboard after login
- [ ] Logout works correctly

### Dashboard
- [ ] Dashboard loads
- [ ] All cards display
- [ ] Stats show (even if 0)
- [ ] No console errors

### Pages
- [ ] Devices page loads
- [ ] Register Device page loads
- [ ] FOX Intelligence page loads
- [ ] Reports page loads
- [ ] Settings page loads
- [ ] Profile page loads

### API Endpoints
- [ ] `/health` - Returns healthy status
- [ ] `/auth/signup` - Creates user
- [ ] `/auth/login` - Returns token
- [ ] `/devices/` - Returns devices list
- [ ] `/stats/dashboard` - Returns stats
- [ ] `/reports/list` - Returns reports

### Investigation Console
- [ ] Console displays on dashboard
- [ ] Can enter commands
- [ ] Commands execute (may fail without network access)
- [ ] Output displays

## Security Verification

- [ ] No `.env` file in GitHub
- [ ] No database files (`.db`) in GitHub
- [ ] No log files in GitHub
- [ ] No API keys visible in code
- [ ] No passwords in code
- [ ] SECRET_KEY is random and secure
- [ ] HTTPS enabled (automatic on Vercel/Render)
- [ ] CORS properly configured

## Documentation

- [ ] README updated with live URLs
- [ ] Deployment guide accessible
- [ ] Environment variables documented
- [ ] Known limitations documented

## Monitoring Setup

- [ ] Backend logs accessible
- [ ] Frontend logs accessible (Vercel dashboard)
- [ ] Database monitoring enabled
- [ ] Error tracking configured (optional)

## Post-Deployment

- [ ] Test all features end-to-end
- [ ] Share URLs with team/users
- [ ] Monitor for errors in first 24 hours
- [ ] Document any issues found
- [ ] Plan for scaling if needed

## Known Limitations (Document These)

- [ ] Network scanning limited without host access
- [ ] Packet capture not available in cloud environment
- [ ] Router integration requires local deployment
- [ ] Some features work better on local network
- [ ] Investigation console commands may have limited functionality

## Rollback Plan

If deployment fails:

1. Check logs for errors
2. Verify environment variables
3. Test database connection
4. Revert to previous deployment if needed
5. Fix issues locally first
6. Redeploy

## Success Criteria

✅ Deployment is successful when:

- Frontend loads without errors
- Backend API responds
- Database connected
- Can signup/login
- Dashboard displays
- No critical errors in logs
- HTTPS working
- CORS configured correctly

---

**Once all items checked, deployment is complete! 🚀**

## Live URLs

**Frontend**: https://_____.vercel.app
**Backend**: https://_____.onrender.com
**API Docs**: https://_____.onrender.com/docs

**Database**: Neon/Supabase (connection string in environment variables)

---

## Next Steps After Deployment

1. Monitor logs for 24-48 hours
2. Test with real users
3. Gather feedback
4. Fix any bugs found
5. Plan feature improvements
6. Consider upgrading to paid tiers if needed
