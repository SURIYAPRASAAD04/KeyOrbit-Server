from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from app.config import Config
import logging

logger = logging.getLogger(__name__)

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
                    <img src="https://i.ibb.co/vCWbbHFh/keyorbit-logo.png" 
                         alt="KeyOrbit Logo" 
                         style="max-width: 180px; height: auto; filter: brightness(1.2);">
                </div>
            </div>
            """
        
        html = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>{title}</title>
            </head>
            <body style="font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #ffffff; margin: 0; padding: 40px 20px; background: linear-gradient(135deg, #0D0D59 0%, #1a1a7e 25%, #2d2db8 50%, #F28C00 100%); min-height: 100vh;">
                <div style="max-width: 600px; margin: 0 auto;">
                    <div style="width: 100%; background: rgba(255, 255, 255, 0.08); backdrop-filter: blur(20px); border-radius: 24px; overflow: hidden; box-shadow: 0 20px 40px rgba(13, 13, 89, 0.3); border: 1px solid rgba(255, 255, 255, 0.15);">
                        {logo_html}
                        <div style="background: linear-gradient(135deg, rgba(13, 13, 89, 0.9) 0%, rgba(242, 140, 0, 0.8) 100%); padding: 40px 30px; text-align: center;">
                            <h1 style="margin: 0; font-size: 32px; font-weight: 700; color: white; text-shadow: 0 2px 10px rgba(0, 0, 0, 0.3);">KeyOrbit KMS</h1>
                            <p style="margin: 8px 0 0 0; opacity: 0.9; font-size: 16px; color: white;">Enterprise Key Management System</p>
                        </div>
                        <div style="padding: 50px 40px; background: rgba(255, 255, 255, 0.05);">
                            {content}
                        </div>
                        <div style="text-align: center; padding: 30px 40px; background: rgba(13, 13, 89, 0.2); color: rgba(255, 255, 255, 0.7); font-size: 13px; border-top: 1px solid rgba(255, 255, 255, 0.1);">
                            <p style="margin: 0;">© 2025 KeyOrbit KMS. All rights reserved.</p>
                            <p style="margin: 8px 0 0 0;">This is an automated message. Please do not reply to this email.</p>
                        </div>
                    </div>
                </div>
            </body>
            </html>
            """
        return html

    @staticmethod
    def _send_email_via_api(to_email, subject, html_content):
        """Send email using SendGrid Web API (uses HTTPS, always works)"""
        try:
            logger.info(f"Attempting to send email to {to_email} via SendGrid API")
            
            message = Mail(
                from_email=Config.FROM_EMAIL,
                to_emails=to_email,
                subject=subject,
                html_content=html_content
            )
            
            sg = SendGridAPIClient(Config.SENDGRID_API_KEY)
            response = sg.send(message)
            
            if response.status_code in [200, 201, 202]:
                logger.info(f"Email sent successfully to {to_email}")
                return True
            else:
                logger.error(f"SendGrid returned status {response.status_code}")
                return False
                
        except Exception as e:
            logger.error(f"Email sending failed to {to_email}: {str(e)}")
            return False

    @staticmethod
    def send_verification_email(email, code, name):
        """Send email verification code"""
        subject = "Verify Your KeyOrbit Account"
        
        content = f"""
        <h2 style="margin-top: 0; color: #ffffff; font-size: 28px; font-weight: 600;">Hello {name},</h2>
        <p style="color: rgba(255, 255, 255, 0.9); font-size: 16px; line-height: 1.6; margin: 15px 0;">Thank you for registering with KeyOrbit. Please use the verification code below to complete your registration:</p>
        
        <div style="background: rgba(13, 13, 89, 0.3); border-radius: 20px; padding: 30px; margin: 35px 0; border: 1px solid rgba(242, 140, 0, 0.3); text-align: center;">
            <div style="font-size: 36px; font-weight: 800; letter-spacing: 12px; color: #ffffff; font-family: monospace;">{code}</div>
        </div>
        
        <p style="color: rgba(255, 255, 255, 0.8); font-size: 14px; text-align: center; margin: 15px 0;">
            This code will expire in 30 minutes. If you didn't request this, please ignore this email.
        </p>
        """
        
        html = EmailService._create_email_template(subject, content)
        return EmailService._send_email_via_api(email, subject, html)

    @staticmethod
    def send_welcome_email(email, name):
        """Send welcome email to new users"""
        subject = "Welcome to KeyOrbit - Your Enterprise Security Journey Begins"
        
        content = f"""
        <h2 style="margin-top: 0; color: #ffffff; font-size: 28px; font-weight: 600;">Welcome to KeyOrbit, {name}!</h2>
        
        <p style="color: rgba(255, 255, 255, 0.9); font-size: 16px; line-height: 1.6; margin: 15px 0;">We're thrilled to have you join our community. Your account has been successfully created and is ready to use.</p>
        
        <div style="text-align: center; margin: 30px 0;">
            <a href="{Config.FRONTEND_URL}/dashboard" style="display: inline-block; padding: 16px 32px; background: #F28C00; color: white; text-decoration: none; border-radius: 16px; font-weight: 600; font-size: 16px;">Launch Your Dashboard</a>
        </div>
        """
        
        html = EmailService._create_email_template(subject, content)
        return EmailService._send_email_via_api(email, subject, html)

    @staticmethod
    def send_password_reset_email(email, reset_token, name):
        """Send password reset email"""
        subject = "Reset Your KeyOrbit Password"
        reset_url = f"{Config.FRONTEND_URL}/reset-password?token={reset_token}"
        
        content = f"""
        <h2 style="margin-top: 0; color: #ffffff; font-size: 28px; font-weight: 600;">Hello {name},</h2>
        
        <p style="color: rgba(255, 255, 255, 0.9); font-size: 16px; line-height: 1.6; margin: 15px 0;">We received a request to reset your KeyOrbit account password. Click the button below to create a new password:</p>
        
        <div style="text-align: center; margin: 30px 0;">
            <a href="{reset_url}" style="display: inline-block; padding: 16px 32px; background: #ef4444; color: white; text-decoration: none; border-radius: 16px; font-weight: 600; font-size: 16px;">Reset Password</a>
        </div>
        
        <p style="color: rgba(255, 255, 255, 0.8); font-size: 14px; text-align: center; margin: 15px 0;">
            This link will expire in 1 hour. If you didn't request this, please ignore this email.
        </p>
        """
        
        html = EmailService._create_email_template(subject, content)
        return EmailService._send_email_via_api(email, subject, html)
    
    @staticmethod
    def send_user_invitation_email(email, invitation_token, organization_name, inviter_name, role, message="", is_resend=False):
        """Send user invitation email"""
        subject = f"Join {organization_name} on KeyOrbit" if not is_resend else f"Reminder: Join {organization_name} on KeyOrbit"
        accept_url = f"{Config.FRONTEND_URL}/accept-invitation?token={invitation_token}"
        
        role_display = {
            'admin': 'Administrator',
            'administrator': 'Administrator',
            'manager': 'Manager',
            'developer': 'Developer',
            'auditor': 'Auditor',
            'viewer': 'Viewer',
            'user': 'User'
        }.get(role, role.capitalize())
        
        content = f"""
        <h2 style="margin-top: 0; color: #ffffff; font-size: 28px; font-weight: 600;">
            You're Invited to Join {organization_name}
        </h2>
        
        <p style="color: rgba(255, 255, 255, 0.9); font-size: 16px; line-height: 1.6; margin: 15px 0;">
            <strong>{inviter_name}</strong> has invited you to join <strong>{organization_name}</strong> on KeyOrbit.
            You've been assigned the role of <strong>{role_display}</strong>.
        </p>
        
        {f'<p style="color: rgba(255, 255, 255, 0.8); font-size: 15px; font-style: italic;">"{message}"</p>' if message else ''}
        
        <div style="text-align: center; margin: 30px 0;">
            <a href="{accept_url}" style="display: inline-block; padding: 16px 32px; background: #F28C00; color: white; text-decoration: none; border-radius: 16px; font-weight: 600; font-size: 16px;">Accept Invitation</a>
        </div>
        
        <p style="color: rgba(255, 255, 255, 0.8); font-size: 14px; text-align: center; margin: 15px 0;">
            This invitation will expire in 7 days. If you didn't expect this invitation, please ignore this email.
        </p>
        """
        
        html = EmailService._create_email_template(subject, content)
        return EmailService._send_email_via_api(email, subject, html)
    
    @staticmethod
    def send_admin_notification_email(admin_email, user_email, user_name):
        """Send notification to admin about new user registration"""
        subject = "New User Registration - KeyOrbit"
        
        content = f"""
        <h2 style="margin-top: 0; color: #ffffff; font-size: 28px; font-weight: 600;">New User Registration</h2>
        
        <p style="color: rgba(255, 255, 255, 0.9); font-size: 16px; line-height: 1.6; margin: 15px 0;">A new user has registered on your KeyOrbit instance:</p>
        
        <div style="background: rgba(255, 255, 255, 0.08); border-radius: 16px; padding: 25px; margin: 20px 0;">
            <p style="margin: 0;"><strong>Name:</strong> {user_name}</p>
            <p style="margin: 10px 0 0 0;"><strong>Email:</strong> {user_email}</p>
        </div>
        
        <div style="text-align: center; margin: 30px 0;">
            <a href="{Config.FRONTEND_URL}/admin/users" style="display: inline-block; padding: 16px 32px; background: #F28C00; color: white; text-decoration: none; border-radius: 16px; font-weight: 600;">View User Management</a>
        </div>
        """
        
        html = EmailService._create_email_template(subject, content)
        return EmailService._send_email_via_api(admin_email, subject, html)