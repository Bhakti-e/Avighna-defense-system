"use client";

import { useState } from "react";
import { Shield, Mail, AlertCircle, CheckCircle, ArrowLeft } from "lucide-react";

export default function ForgotPasswordPage() {
  const [email, setEmail] = useState("");
  const [submitted, setSubmitted] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    // Placeholder - password reset not implemented yet
    setSubmitted(true);
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-background via-background to-primary/5">
      <div className="w-full max-w-md p-8">
        {/* Logo and Title */}
        <div className="text-center mb-8">
          <div className="flex items-center justify-center mb-4">
            <Shield className="w-16 h-16 text-primary" />
          </div>
          <h1 className="text-3xl font-bold mb-2">AVIGHNA Defense</h1>
          <p className="text-muted-foreground">Reset your password</p>
        </div>

        {/* Form */}
        <div className="glass rounded-lg p-8">
          <h2 className="text-2xl font-semibold mb-6">Forgot Password</h2>

          {!submitted ? (
            <>
              <p className="text-sm text-muted-foreground mb-6">
                Enter your email address and we'll send you instructions to reset your password.
              </p>

              <div className="mb-6 p-3 bg-warning/20 border border-warning/50 rounded-lg flex items-start space-x-2 text-warning">
                <AlertCircle className="w-4 h-4 mt-0.5 flex-shrink-0" />
                <span className="text-sm">
                  Password reset functionality is currently under development. Please contact your administrator.
                </span>
              </div>

              <form onSubmit={handleSubmit} className="space-y-4">
                {/* Email */}
                <div>
                  <label className="block text-sm font-medium mb-2">Email Address</label>
                  <div className="relative">
                    <Mail className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-muted-foreground" />
                    <input
                      type="email"
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      placeholder="your@email.com"
                      className="w-full pl-10 pr-4 py-2 bg-background/50 border border-border rounded-lg focus:outline-none focus:ring-2 focus:ring-primary"
                      required
                      disabled
                    />
                  </div>
                </div>

                {/* Submit Button */}
                <button
                  type="submit"
                  disabled
                  className="w-full px-4 py-3 bg-primary text-primary-foreground rounded-lg hover:bg-primary/90 transition-colors disabled:opacity-50 disabled:cursor-not-allowed font-medium"
                >
                  Send Reset Instructions
                </button>
              </form>
            </>
          ) : (
            <div className="space-y-4">
              <div className="p-4 bg-success/20 border border-success/50 rounded-lg flex items-start space-x-3 text-success">
                <CheckCircle className="w-5 h-5 mt-0.5 flex-shrink-0" />
                <div>
                  <p className="font-medium">Instructions sent!</p>
                  <p className="text-sm mt-1">
                    If an account exists with {email}, you will receive password reset instructions.
                  </p>
                </div>
              </div>
            </div>
          )}

          {/* Back to Login */}
          <div className="mt-6">
            <a
              href="/login"
              className="flex items-center justify-center space-x-2 text-sm text-primary hover:underline"
            >
              <ArrowLeft className="w-4 h-4" />
              <span>Back to login</span>
            </a>
          </div>
        </div>

        {/* Footer */}
        <div className="mt-8 text-center text-sm text-muted-foreground">
          <p>AVIGHNA Defense v3.0</p>
        </div>
      </div>
    </div>
  );
}
