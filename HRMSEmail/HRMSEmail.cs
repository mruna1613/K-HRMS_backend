using System.Net;
using System.Net.Mail;

namespace backend.HRMSEmail
{
    public static class HRMSEmail
    {
        public static void SendResetPasswordEmail(string recipient, string newPassword)
        {
            // Configure the email settings
            string senderEmail = "rutuja.22110140@viit.ac.in";
            string senderPassword = "!07@rutuja#";
            string smtpServer = "smtp.example.com";
            int smtpPort = 587;

            // Create a MailMessage
            MailMessage mail = new MailMessage();
            mail.From = new MailAddress(senderEmail);
            mail.To.Add(recipient);
            mail.Subject = "Password Reset";
            mail.Body = $"Your password has been reset. Your new password is: {newPassword}";

            // Configure the SMTP client
            SmtpClient smtpClient = new SmtpClient(smtpServer);
            smtpClient.Port = smtpPort;
            smtpClient.Credentials = new NetworkCredential(senderEmail, senderPassword);
            smtpClient.EnableSsl = true;

            // Send the email
            try
            {
                smtpClient.Send(mail);
            }
            catch (Exception ex)
            {
                // Handle the exception (log it or take appropriate action)
                Console.WriteLine($"Failed to send email: {ex.Message}");
            }
            finally
            {
                // Dispose of resources
                mail.Dispose();
                smtpClient.Dispose();
            }
        }

        public static void SendOTPEmail(string strEmpCode, string strOtp)
        {
            try
            {
                // Your email configuration settings
                string smtpServer = "smtp.example.com";
                int smtpPort = 587; // Your SMTP server port
                string smtpUsername = "your_username";
                string smtpPassword = "your_password";

                // Sender and recipient email addresses
                string senderEmail = "your_email@example.com";
                string recipientEmail = "recipient_email@example.com";

                // Create and configure the SMTP client
                using (var client = new SmtpClient(smtpServer, smtpPort))
                {
                    client.UseDefaultCredentials = false;
                    client.Credentials = new NetworkCredential(smtpUsername, smtpPassword);
                    client.EnableSsl = true;

                    // Create and configure the email message
                    var message = new MailMessage(senderEmail, recipientEmail)
                    {
                        Subject = "Your OTP",
                        Body = $"Your OTP for employee code {strEmpCode} is {strOtp}.",
                        IsBodyHtml = true
                    };

                    // Send the email
                    client.Send(message);
                }
            }
            catch (Exception ex)
            {
                // Handle the exception or log it
                Console.WriteLine($"Error sending OTP email: {ex.Message}");
            }
        }
    }
}
