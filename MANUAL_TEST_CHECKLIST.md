# AVIGHNA Defense System - Manual Testing Checklist

## 🚀 System Status

- ✅ Backend: Running on http://localhost:8000
- ✅ Frontend: Running on http://localhost:3000
- ✅ Database: Connected (SQLite)
- ✅ API Tests: 95% passing

## 🧪 Manual Testing Instructions

### Test Credentials
- **Username:** `final_1777829362`
- **Password:** `test123`

Or create a new account during testing.

---

## 📋 Test Checklist

### 1. Authentication Flow
- [ ] Open http://localhost:3000
- [ ] Should redirect to `/login`
- [ ] Click "Sign up" link
- [ ] Fill signup form with new credentials
- [ ] Submit - should redirect to dashboard
- [ ] Logout from profile dropdown
- [ ] Login again with same credentials
- [ ] Should see dashboard without redirect loop

**Expected:** Smooth authentication flow, no redirect loops

---

### 2. Dashboard Page (`/`)

#### Stats Cards
- [ ] Total Devices card shows count
- [ ] Active Alerts card shows count
- [ ] Reconnaissance Events card shows count
- [ ] System Status card shows status

#### Quick Action Cards
- [ ] "Register Device" card (green glow)
- [ ] "View Devices" card (green glow)
- [ ] "Active Alerts" card (red glow)
- [ ] "Reconnaissance" card (red glow)
- [ ] "Observation" card (yellow glow)
- [ ] "Isolation" card (orange glow)
- [ ] "FOX Intel" card (blue glow)
- [ ] "Reports" card (blue glow)
- [ ] All cards clickable and navigate correctly

#### Investigation Console
- [ ] Console visible at bottom of dashboard
- [ ] Try command: `ping 8.8.8.8 -n 2`
- [ ] Output appears in console
- [ ] Try invalid command (should be blocked)
- [ ] Command history works

**Expected:** All stats load, cards glow subtly, console executes whitelisted commands

---

### 3. Register Device Page (`/register`)

- [ ] Form has fields: Nickname, MAC Address, IP Address, Device Type
- [ ] Try registering with:
  - Nickname: "Test Laptop"
  - MAC: "AA:BB:CC:DD:EE:FF"
  - IP: "192.168.1.100"
  - Type: "laptop"
- [ ] Submit form
- [ ] Check if device appears in devices list

**Expected:** Form validation works, device registration succeeds or shows clear error

---

### 4. Devices Page (`/devices`)

- [ ] Shows list of discovered devices
- [ ] Shows manually registered devices
- [ ] Device cards show: IP, MAC, Name, Type, Status
- [ ] Can click on device for details
- [ ] Can perform actions (isolate, observe, etc.)

**Expected:** All devices visible with correct information

---

### 5. Alerts Page (`/alerts`)

- [ ] Shows list of alerts (may be empty)
- [ ] Alert cards show: Severity, Type, Time, Device
- [ ] Can acknowledge alerts
- [ ] Can resolve alerts
- [ ] Filters work (if any)

**Expected:** Alerts page loads, actions work

---

### 6. FOX Threat Intelligence (`/threat-intelligence`)

- [ ] Page loads without errors
- [ ] Shows threat intelligence feed (or placeholder)
- [ ] Shows IOCs (Indicators of Compromise)
- [ ] Can search/filter threats

**Expected:** Page loads (may show "Coming Soon" or placeholder data)

---

### 7. Reports Page (`/reports`)

- [ ] Shows list of generated reports
- [ ] Can generate new report
- [ ] Can download reports
- [ ] Reports show: Date, Type, Device, Status

**Expected:** Reports list loads, generation works

---

### 8. Reconnaissance Page (`/recon`)

- [ ] Shows reconnaissance events
- [ ] Events show: Source, Target, Type, Time
- [ ] Can view event details
- [ ] Can take actions on suspicious events

**Expected:** Recon events visible (may be empty)

---

### 9. Isolation Page (`/isolation`)

- [ ] Shows isolated devices
- [ ] Device cards show isolation reason
- [ ] Can restore devices to normal
- [ ] Shows isolation timeline

**Expected:** Isolation page loads, restore action works

---

### 10. Observation Page (`/observation`)

- [ ] Shows devices under observation
- [ ] Device cards show observation reason
- [ ] Can restore devices to normal
- [ ] Shows observation logs

**Expected:** Observation page loads, restore action works

---

### 11. Profile Page (`/profile`)

- [ ] Shows current user info
- [ ] Can update: Avatar, Username, Email, Full Name
- [ ] Can change password
- [ ] Dark mode toggle works
- [ ] Changes save successfully

**Expected:** Profile loads, updates work (or show "Coming Soon")

---

### 12. Settings Page (`/settings`)

- [ ] Shows system settings
- [ ] Network scan frequency setting
- [ ] Notification preferences
- [ ] Threat detection thresholds
- [ ] Can save changes

**Expected:** Settings load, updates work (or show "Coming Soon")

---

### 13. Navigation & UI

#### Sidebar
- [ ] Shows: Dashboard, Register Device, FOX, Reports, Settings
- [ ] System Status card at bottom
- [ ] Logout button at bottom
- [ ] All links work correctly

#### Topbar
- [ ] Shows "AVIGHNA Defense"
- [ ] Notification bell (top right)
- [ ] Profile dropdown: "🟢 Username ▼"
- [ ] Dropdown shows: Profile, Logout
- [ ] Dropdown appears above all content (z-index)

#### General UI
- [ ] Card glows are subtle (not overwhelming)
- [ ] Dark theme looks good
- [ ] Responsive on different screen sizes
- [ ] No console errors in browser DevTools
- [ ] Loading states work
- [ ] Error messages are clear

**Expected:** Clean, professional UI with smooth interactions

---

## 🐛 Bug Reporting

If you find issues, note:
1. **Page:** Which page/feature
2. **Action:** What you did
3. **Expected:** What should happen
4. **Actual:** What actually happened
5. **Console:** Any browser console errors
6. **Network:** Any failed API calls (check Network tab)

---

## ✅ Success Criteria

- [ ] No redirect loops on login
- [ ] All pages load without errors
- [ ] Dashboard shows real data
- [ ] Device registration works
- [ ] Investigation console executes commands
- [ ] Navigation works smoothly
- [ ] UI looks professional
- [ ] No critical console errors

---

## 📊 Test Results

**Date:** _____________
**Tester:** _____________
**Overall Status:** ⬜ Pass / ⬜ Fail
**Notes:**

---

## 🚀 After Testing

If all tests pass:
1. ✅ System is ready for deployment
2. ✅ Can proceed with Vercel + Render deployment
3. ✅ Can push to GitHub

If tests fail:
1. Document issues in bug report
2. Fix critical bugs
3. Re-test
4. Repeat until all pass
