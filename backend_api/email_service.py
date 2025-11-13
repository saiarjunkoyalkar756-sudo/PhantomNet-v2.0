import os
import logging

logger = logging.getLogger(__name__)

def send_reset_email(to_email: str, reset_link: str):
    """
    Sends a password reset email to the specified address.
    For now, this function logs the email content to the console.
    In a production environment, this would integrate with an email sending service (e.g., SendGrid, SES).
    """
    subject = "PhantomNet Password Reset Request"
    body = f"""
Hello,

You have requested a password reset for your PhantomNet account.

Please click on the following link to reset your password:
{reset_link}

This link will expire in 15 minutes.

If you did not request a password reset, please ignore this email.

Sincerely,
The PhantomNet Team
"""

    logger.info(f"--- SIMULATED EMAIL SEND ---")
    logger.info(f"To: {to_email}")
    logger.info(f"Subject: {subject}")
    logger.info(f"Body:\n{body}")
    logger.info(f"----------------------------")

    # In a real implementation, you would use an email sending library/API here.
    # Example with SendGrid (requires sendgrid library and API key):
    # from sendgrid import SendGridAPIClient
    # from sendgrid.helpers.mail import Mail
    # 
    # SENDGRID_API_KEY = os.getenv("EMAIL_API_KEY")
    # if SENDGRID_API_KEY:
    #     message = Mail(
    #         from_email='noreply@phantomnet.com',
    #         to_emails=to_email,
    #         subject=subject,
    #         html_content=body)
    #     try:
    #         sg = SendGridAPIClient(SENDGRID_API_KEY)
    #         response = sg.send(message)
    #         logger.info(f"Email sent via SendGrid. Status Code: {response.status_code}")
    #     except Exception as e:
    #         logger.error(f"Error sending email via SendGrid: {e}")
    # else:
    #     logger.warning("EMAIL_API_KEY not set. Email not sent via SendGrid.")
