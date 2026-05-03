"use client";

import { useState, useEffect } from "react";
import { User, Mail, Lock, Image, Moon, Sun } from "lucide-react";

export default function ProfilePage() {
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [darkMode, setDarkMode] = useState(true);

  useEffect(() => {
    const user = localStorage.getItem("avighna_user");
    if (user) setUsername(user);
  }, []);

  const handleSaveProfile = () => {
    alert("Profile updated successfully");
  };

  const handleChangePassword = () => {
    if (newPassword !== confirmPassword) {
      alert("Passwords do not match");
      return;
    }
    alert("Password changed successfully");
    setCurrentPassword("");
    setNewPassword("");
    setConfirmPassword("");
  };

  return (
    <div className="p-8 space-y-6">
      <div className="flex items-center space-x-3">
        <User className="w-8 h-8 text-primary" />
        <div>
          <h1 className="text-3xl font-bold">Profile</h1>
          <p className="text-muted-foreground">Manage your personal settings</p>
        </div>
      </div>

      <div className="grid gap-6 max-w-2xl">
        {/* Avatar Section */}
        <div className="glass p-6 rounded-lg space-y-4">
          <div className="flex items-center space-x-2 mb-4">
            <Image className="w-5 h-5 text-primary" />
            <h2 className="text-xl font-semibold">Avatar</h2>
          </div>
          
          <div className="flex items-center space-x-4">
            <div className="w-20 h-20 rounded-full bg-primary flex items-center justify-center text-2xl font-bold">
              {username[0]?.toUpperCase() || "U"}
            </div>
            <div>
              <button className="px-4 py-2 bg-primary/20 text-primary rounded-lg hover:bg-primary/30 transition-colors text-sm">
                Upload Avatar
              </button>
              <p className="text-xs text-muted-foreground mt-2">
                JPG, PNG or GIF. Max 2MB.
              </p>
            </div>
          </div>
        </div>

        {/* Personal Information */}
        <div className="glass p-6 rounded-lg space-y-4">
          <div className="flex items-center space-x-2 mb-4">
            <User className="w-5 h-5 text-primary" />
            <h2 className="text-xl font-semibold">Personal Information</h2>
          </div>
          
          <div>
            <label className="block text-sm font-medium mb-2">Username</label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="w-full px-4 py-2 bg-card border border-border rounded-lg focus:outline-none focus:ring-2 focus:ring-primary"
              placeholder="Enter username"
            />
          </div>
          
          <div>
            <label className="block text-sm font-medium mb-2">Email</label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full px-4 py-2 bg-card border border-border rounded-lg focus:outline-none focus:ring-2 focus:ring-primary"
              placeholder="Enter email"
            />
          </div>

          <button
            onClick={handleSaveProfile}
            className="w-full py-2 bg-primary text-white rounded-lg hover:bg-primary/90 transition-colors font-medium"
          >
            Save Changes
          </button>
        </div>

        {/* Change Password */}
        <div className="glass p-6 rounded-lg space-y-4">
          <div className="flex items-center space-x-2 mb-4">
            <Lock className="w-5 h-5 text-primary" />
            <h2 className="text-xl font-semibold">Change Password</h2>
          </div>
          
          <div>
            <label className="block text-sm font-medium mb-2">Current Password</label>
            <input
              type="password"
              value={currentPassword}
              onChange={(e) => setCurrentPassword(e.target.value)}
              className="w-full px-4 py-2 bg-card border border-border rounded-lg focus:outline-none focus:ring-2 focus:ring-primary"
              placeholder="Enter current password"
            />
          </div>
          
          <div>
            <label className="block text-sm font-medium mb-2">New Password</label>
            <input
              type="password"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              className="w-full px-4 py-2 bg-card border border-border rounded-lg focus:outline-none focus:ring-2 focus:ring-primary"
              placeholder="Enter new password"
            />
          </div>
          
          <div>
            <label className="block text-sm font-medium mb-2">Confirm New Password</label>
            <input
              type="password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              className="w-full px-4 py-2 bg-card border border-border rounded-lg focus:outline-none focus:ring-2 focus:ring-primary"
              placeholder="Confirm new password"
            />
          </div>

          <button
            onClick={handleChangePassword}
            className="w-full py-2 bg-primary text-white rounded-lg hover:bg-primary/90 transition-colors font-medium"
          >
            Change Password
          </button>
        </div>

        {/* Appearance */}
        <div className="glass p-6 rounded-lg space-y-4">
          <div className="flex items-center space-x-2 mb-4">
            {darkMode ? <Moon className="w-5 h-5 text-primary" /> : <Sun className="w-5 h-5 text-primary" />}
            <h2 className="text-xl font-semibold">Appearance</h2>
          </div>
          
          <div className="flex items-center justify-between">
            <div>
              <p className="font-medium">Dark Mode</p>
              <p className="text-sm text-muted-foreground">Toggle dark/light theme</p>
            </div>
            <button
              onClick={() => setDarkMode(!darkMode)}
              className={`relative w-14 h-7 rounded-full transition-colors ${
                darkMode ? "bg-primary" : "bg-muted"
              }`}
            >
              <span
                className={`absolute top-1 left-1 w-5 h-5 bg-white rounded-full transition-transform ${
                  darkMode ? "translate-x-7" : ""
                }`}
              ></span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
