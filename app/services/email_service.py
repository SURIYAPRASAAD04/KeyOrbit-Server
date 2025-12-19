import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.image import MIMEImage
import os
from app.config import Config

class EmailService:
    @staticmethod
    def _create_email_template(title, content, include_logo=True):
        """Create a glassmorphic email template with modern design"""
        logo_html = ""
        if include_logo:
            logo_html = """
            <div style="text-align: center; margin-bottom: 30px;">
                <div style="
                    display: inline-block;
                    padding: 20px;
                    background: rgba(255, 255, 255, 0.1);
                    border-radius: 20px;
                    backdrop-filter: blur(20px);
                    border: 1px solid rgba(255, 255, 255, 0.2);
                    box-shadow: 0 8px 32px rgba(13, 13, 89, 0.3);
                ">
                    <img src="https://i.ibb.co/gbnZxzVK/Black-White-Modern-Letter-AG-Logo-1-removebg-preview.png" 
                         alt="KeyOrbit Logo" 
                         style="max-width: 180px; height: auto; filter: brightness(1.2);">
                </div>
            </div>
            """
        
        # Inline all CSS styles for email compatibility with centered layout
        html = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>{title}</title>
            </head>
            <body style="font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #ffffff; margin: 0; padding: 40px 20px; background: linear-gradient(135deg, #0D0D59 0%, #1a1a7e 25%, #2d2db8 50%, #F28C00 100%); min-height: 100vh; position: relative; overflow-x: hidden;">
                <!-- Centering container for email clients -->
                <div style="max-width: 600px; margin: 0 auto;">
                    <div style="width: 100%; background: rgba(255, 255, 255, 0.08); backdrop-filter: blur(20px); border-radius: 24px; overflow: hidden; box-shadow: 0 20px 40px rgba(13, 13, 89, 0.3), 0 15px 25px rgba(0, 0, 0, 0.1), inset 0 1px 0 rgba(255, 255, 255, 0.2); border: 1px solid rgba(255, 255, 255, 0.15); position: relative;">
                        {logo_html}
                        <div style="background: linear-gradient(135deg, rgba(13, 13, 89, 0.9) 0%, rgba(242, 140, 0, 0.8) 100%); padding: 40px 30px; text-align: center; color: white; position: relative; overflow: hidden;">
                            <h1 style="margin: 0; font-size: 32px; font-weight: 700; position: relative; z-index: 2; text-shadow: 0 2px 10px rgba(0, 0, 0, 0.3); letter-spacing: -0.5px;">KeyOrbit KMS</h1>
                            <p style="margin: 8px 0 0 0; opacity: 0.9; font-size: 16px; font-weight: 400; position: relative; z-index: 2; letter-spacing: 0.3px;">Enterprise Key Management System</p>
                        </div>
                        <div style="padding: 50px 40px; background: rgba(255, 255, 255, 0.05); backdrop-filter: blur(10px); position: relative;">
                            {content}
                        </div>
                        <div style="text-align: center; padding: 30px 40px; background: rgba(13, 13, 89, 0.2); backdrop-filter: blur(15px); color: rgba(255, 255, 255, 0.7); font-size: 13px; border-top: 1px solid rgba(255, 255, 255, 0.1); position: relative;">
                            <p style="margin: 0;">© 2025 KeyOrbit KMS. All rights reserved.</p>
                            <p style="margin: 8px 0 0 0;">This is an automated message. Please do not reply to this email.</p>
                            <p style="margin: 8px 0 0 0;">
                                <a href="https://keyorbit.com/privacy" style="color: rgba(242, 140, 0, 0.8); text-decoration: none; transition: color 0.3s ease;">Privacy Policy</a> | 
                                <a href="https://keyorbit.com/terms" style="color: rgba(242, 140, 0, 0.8); text-decoration: none; transition: color 0.3s ease;">Terms of Service</a> | 
                                <a href="https://keyorbit.com/contact" style="color: rgba(242, 140, 0, 0.8); text-decoration: none; transition: color 0.3s ease;">Contact Support</a>
                            </p>
                        </div>
                    </div>
                </div>
            </body>
            </html>
            """

        return html

    @staticmethod
    def send_verification_email(email, code, name):
        """Send email verification code"""
        subject = "Verify Your KeyOrbit Account"
        
        content = f"""
        <h2 style="margin-top: 0; color: #ffffff; font-size: 28px; font-weight: 600; letter-spacing: -0.3px;">Hello {name},</h2>
        <p style="color: rgba(255, 255, 255, 0.9); font-size: 16px; line-height: 1.6; margin: 15px 0;">Thank you for registering with KeyOrbit. Please use the verification code below to complete your registration:</p>
        
        <div style="background: rgba(13, 13, 89, 0.3); backdrop-filter: blur(20px); border-radius: 20px; padding: 30px; margin: 35px 0; border: 1px solid rgba(242, 140, 0, 0.3); box-shadow: 0 15px 35px rgba(13, 13, 89, 0.4), inset 0 1px 0 rgba(255, 255, 255, 0.1); position: relative; overflow: hidden;">
            <div style="font-size: 36px; font-weight: 800; letter-spacing: 12px; text-align: center; margin: 0; color: #ffffff; font-family: 'SF Mono', Monaco, 'Cascadia Code', monospace; text-shadow: 0 0 20px rgba(242, 140, 0, 0.6); position: relative;">{code}</div>
        </div>
        
        <p style="color: rgba(255, 255, 255, 0.8); font-size: 14px; text-align: center; margin: 15px 0;">
            This code will expire in 30 minutes. If you didn't request this, please ignore this email.
        </p>
        
        <div style="background: rgba(16, 185, 129, 0.15); backdrop-filter: blur(10px); border-radius: 16px; padding: 25px; margin: 20px 0; border: 1px solid rgba(16, 185, 129, 0.3); border-left: 4px solid #10B981; box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1), inset 0 1px 0 rgba(255, 255, 255, 0.1); position: relative;">
            <p style="margin: 0; color: rgba(255, 255, 255, 0.9); font-size: 14px;">
                <strong>Security Tip:</strong> Never share your verification code with anyone. 
                KeyOrbit staff will never ask for your verification code.
            </p>
        </div>
        """
        
        html = EmailService._create_email_template(subject, content)
        
        return EmailService._send_email(email, subject, html)

    @staticmethod
    def send_welcome_email(email, name):
        """Send welcome email to new users"""
        subject = "Welcome to KeyOrbit - Your Enterprise Security Journey Begins"
        
        content = f"""
        <h2 style="margin-top: 0; color: #ffffff; font-size: 28px; font-weight: 600; letter-spacing: -0.3px;">Welcome to KeyOrbit, {name}!</h2>
        
        <p style="color: rgba(255, 255, 255, 0.9); font-size: 16px; line-height: 1.6; margin: 15px 0;">We're thrilled to have you join our community of security-conscious enterprises. 
        Your account has been successfully created and is ready to use.</p>
        
        <div style="text-align: center; margin: 30px 0;">
            <a href="https://app.keyorbit.com/dashboard" style="display: inline-block; padding: 16px 32px; background: rgba(242, 140, 0, 0.2); backdrop-filter: blur(20px); color: white; text-decoration: none; border-radius: 16px; font-weight: 600; font-size: 16px; margin: 25px 0; transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1); border: 1px solid rgba(242, 140, 0, 0.3); box-shadow: 0 8px 32px rgba(242, 140, 0, 0.3), inset 0 1px 0 rgba(255, 255, 255, 0.2); position: relative; overflow: hidden; letter-spacing: 0.5px;">
                Launch Your Dashboard
            </a>
        </div>
        
        <div style="margin: 30px 0; gap: 20px;">
            <h3 style="color: #ffffff; font-size: 22px; font-weight: 600; letter-spacing: -0.3px; margin: 25px 0 15px 0;">Get Started with KeyOrbit</h3>
            
            <div style="background: rgba(255, 255, 255, 0.06); backdrop-filter: blur(10px); padding: 24px; border-radius: 16px; border: 1px solid rgba(255, 255, 255, 0.1); margin: 16px 0; box-shadow: 0 8px 25px rgba(0, 0, 0, 0.1), inset 0 1px 0 rgba(255, 255, 255, 0.1); transition: all 0.3s ease; position: relative; overflow: hidden;">
                <div style="font-weight: 600; font-size: 18px; color: #ffffff; margin: 0 0 8px 0; letter-spacing: 0.3px;">Secure Your Keys</div>
                <p style="margin: 0; color: rgba(255, 255, 255, 0.8); font-size: 15px; line-height: 1.5;">Generate and manage cryptographic keys with enterprise-grade security</p>
            </div>
            
            <div style="background: rgba(255, 255, 255, 0.06); backdrop-filter: blur(10px); padding: 24px; border-radius: 16px; border: 1px solid rgba(255, 255, 255, 0.1); margin: 16px 0; box-shadow: 0 8px 25px rgba(0, 0, 0, 0.1), inset 0 1px 0 rgba(255, 255, 255, 0.1); transition: all 0.3s ease; position: relative; overflow: hidden;">
                <div style="font-weight: 600; font-size: 18px; color: #ffffff; margin: 0 0 8px 0; letter-spacing: 0.3px;">Team Collaboration</div>
                <p style="margin: 0; color: rgba(255, 255, 255, 0.8); font-size: 15px; line-height: 1.5;">Invite team members and set up role-based access control</p>
            </div>
            
            <div style="background: rgba(255, 255, 255, 0.06); backdrop-filter: blur(10px); padding: 24px; border-radius: 16px; border: 1px solid rgba(255, 255, 255, 0.1); margin: 16px 0; box-shadow: 0 8px 25px rgba(0, 0, 0, 0.1), inset 0 1px 0 rgba(255, 255, 255, 0.1); transition: all 0.3s ease; position: relative; overflow: hidden;">
                <div style="font-weight: 600; font-size: 18px; color: #ffffff; margin: 0 0 8px 0; letter-spacing: 0.3px;">Monitor Activity</div>
                <p style="margin: 0; color: rgba(255, 255, 255, 0.8); font-size: 15px; line-height: 1.5;">Track all cryptographic operations with comprehensive audit logs</p>
            </div>
        </div>
        
        <div style="background: rgba(59, 130, 246, 0.15); backdrop-filter: blur(10px); border-radius: 16px; padding: 25px; margin: 20px 0; border: 1px solid rgba(59, 130, 246, 0.3); box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1), inset 0 1px 0 rgba(255, 255, 255, 0.1); position: relative;">
            <h4 style="margin: 0 0 15px 0; color: #ffffff; font-size: 18px; font-weight: 600;">Need Help Getting Started?</h4>
            <p style="margin: 0; color: rgba(255, 255, 255, 0.9);">
                • Check out our <a href="https://keyorbit.com/docs" style="color: #F28C00;">documentation</a><br>
                • Watch <a href="https://keyorbit.com/tutorials" style="color: #F28C00;">video tutorials</a><br>
                • Contact our <a href="https://keyorbit.com/support" style="color: #F28C00;">support team</a>
            </p>
        </div>
        """
        
        html = EmailService._create_email_template(subject, content)
        
        return EmailService._send_email(email, subject, html)

    @staticmethod
    def send_password_reset_email(email, reset_token, name):
        """Send password reset email"""
        subject = "Reset Your KeyOrbit Password"
        reset_url = f"{Config.FRONTEND_URL}/reset-password?token={reset_token}"
        
        content = f"""
        <h2 style="margin-top: 0; color: #ffffff; font-size: 28px; font-weight: 600; letter-spacing: -0.3px;">Hello {name},</h2>
        
        <p style="color: rgba(255, 255, 255, 0.9); font-size: 16px; line-height: 1.6; margin: 15px 0;">We received a request to reset your KeyOrbit account password. Click the button below to create a new password:</p>
        
        <div style="text-align: center; margin: 30px 0;">
            <a href="{reset_url}" style="display: inline-block; padding: 16px 32px; background: rgba(239, 68, 68, 0.2); backdrop-filter: blur(20px); color: white; text-decoration: none; border-radius: 16px; font-weight: 600; font-size: 16px; margin: 25px 0; transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1); border: 1px solid rgba(239, 68, 68, 0.3); box-shadow: 0 8px 32px rgba(239, 68, 68, 0.3), inset 0 1px 0 rgba(255, 255, 255, 0.2); position: relative; overflow: hidden; letter-spacing: 0.5px;">
                Reset Password
            </a>
        </div>
        
        <p style="color: rgba(255, 255, 255, 0.8); font-size: 14px; text-align: center; margin: 15px 0;">
            This link will expire in 1 hour. If you didn't request a password reset, please ignore this email.
        </p>
        
        <div style="background: rgba(239, 68, 68, 0.15); backdrop-filter: blur(10px); border-radius: 16px; padding: 25px; margin: 20px 0; border: 1px solid rgba(239, 68, 68, 0.3); box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1), inset 0 1px 0 rgba(255, 255, 255, 0.1); position: relative;">
            <p style="margin: 0; color: rgba(255, 255, 255, 0.9); font-size: 14px;">
                <strong>Security Alert:</strong> If you didn't request this password reset, 
                please <a href="https://keyorbit.com/security" style="color: #F28C00;">review your account security</a> immediately.
            </p>
        </div>
        
        <p style="color: rgba(255, 255, 255, 0.9); font-size: 12px; margin-top: 25px; background: rgba(255, 255, 255, 0.06); padding: 12px; border-radius: 8px; border: 1px solid rgba(255, 255, 255, 0.1);">
            Alternatively, you can copy and paste this link in your browser:<br>
            <span style="text-align: center; color: rgba(255, 255, 255, 0.9); padding: 8px; border-radius: 4px; word-break: break-all; font-family: monospace;">{reset_url}</span>
        </p>
        """
        
        html = EmailService._create_email_template(subject, content)
        
        return EmailService._send_email(email, subject, html)
    
    
    @staticmethod
    def send_admin_notification_email(admin_email, user_email, user_name):
        """Send notification to admin about new user registration"""
        subject = "New User Registration - KeyOrbit"
        
        content = f"""
        <h2 style="margin-top: 0; color: #ffffff; font-size: 28px; font-weight: 600; letter-spacing: -0.3px;">New User Registration</h2>
        
        <p style="color: rgba(255, 255, 255, 0.9); font-size: 16px; line-height: 1.6; margin: 15px 0;">A new user has registered on your KeyOrbit instance:</p>
        
        <div style="background: rgba(255, 255, 255, 0.08); backdrop-filter: blur(15px); border-radius: 16px; padding: 25px; margin: 20px 0; border: 1px solid rgba(255, 255, 255, 0.15); box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1), inset 0 1px 0 rgba(255, 255, 255, 0.1); position: relative;">
            <p style="margin: 0;"><strong>Name:</strong> {user_name}</p>
            <p style="margin: 10px 0 0 0;"><strong>Email:</strong> {user_email}</p>
            <p style="margin: 10px 0 0 0;"><strong>Registration Date:</strong> Just now</p>
        </div>
        
        <div style="text-align: center; margin: 30px 0;">
            <a href="https://app.keyorbit.com/admin/users" style="display: inline-block; padding: 16px 32px; background: rgba(242, 140, 0, 0.2); backdrop-filter: blur(20px); color: white; text-decoration: none; border-radius: 16px; font-weight: 600; font-size: 16px; margin: 25px 0; transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1); border: 1px solid rgba(242, 140, 0, 0.3); box-shadow: 0 8px 32px rgba(242, 140, 0, 0.3), inset 0 1px 0 rgba(255, 255, 255, 0.2); position: relative; overflow: hidden; letter-spacing: 0.5px;">
                View User Management
            </a>
        </div>
        
        <div style="background: rgba(59, 130, 246, 0.15); backdrop-filter: blur(10px); border-radius: 16px; padding: 25px; margin: 20px 0; border: 1px solid rgba(59, 130, 246, 0.3); border-left: 4px solid #3B82F6; box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1), inset 0 1px 0 rgba(255, 255, 255, 0.1); position: relative;">
            <p style="margin: 0; color: rgba(255, 255, 255, 0.9); font-size: 14px;">
                This is an automated notification. You can manage email preferences in your admin settings.
            </p>
        </div>
        """
        
        html = EmailService._create_email_template(subject, content)
        
        return EmailService._send_email(admin_email, subject, html)

    @staticmethod
    def _send_email(to_email, subject, html_content):
        """Internal method to send email"""
        try:
            msg = MIMEMultipart()
            msg['From'] = Config.FROM_EMAIL
            msg['To'] = to_email
            msg['Subject'] = subject
            
            # Add HTML content
            msg.attach(MIMEText(html_content, 'html'))
            
            # Connect to SMTP server and send email
            server = smtplib.SMTP(Config.SMTP_SERVER, Config.SMTP_PORT)
            server.starttls()
            server.login(Config.SMTP_USERNAME, Config.SMTP_PASSWORD)
            server.send_message(msg)
            server.quit()
            
            print(f"Email sent successfully to {to_email}")
            return True
            
        except Exception as e:
            print(f"Email sending failed to {to_email}: {str(e)}")
            return False