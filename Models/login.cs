using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using System;
using System.Data.SqlClient;
using System.Security.Cryptography;
using System.Text;

namespace backend.Models.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class LoginController : ControllerBase
    {
        private readonly IConfiguration _configuration;

        public LoginController(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        [HttpPost("{EmpCode}")]
        public IActionResult Login([FromBody] LoginRequest loginRequest)
        {
            try
            {
                if (loginRequest == null || string.IsNullOrEmpty(loginRequest.EmpCode) || string.IsNullOrEmpty(loginRequest.Password))
                {
                    return BadRequest("Invalid request");
                }

                // Connect to your SQL Server database securely (consider using dependency injection)
                string connectionString = _configuration.GetConnectionString("DefaultConnection");

                using (SqlConnection connection = new SqlConnection(connectionString))
                {
                    connection.Open();

                    // Check if the user exists in the database
                    string query = "SELECT TOP 1 EmpCode, Password, Salt, Algo, isactive FROM hrms_app.dbo.empCreds WHERE EmpCode = @EmpCode";

                    using (SqlCommand command = new SqlCommand(query, connection))
                    {
                        command.Parameters.AddWithValue("@EmpCode", loginRequest.EmpCode);

                        using (SqlDataReader reader = command.ExecuteReader())
                        {
                            if (reader.Read())
                            {
                                // User is found, now verify the password
                                var storedPassword = reader["Password"].ToString();
                                var salt = reader["Salt"].ToString().Trim();

                                // Trim extra characters and add padding if needed
                                while (salt.Length % 4 != 0)
                                {
                                    salt += "=";
                                }

                                Console.WriteLine($"Salt from the database: {salt}");
                                var saltBytes = Convert.FromBase64String(salt);

                                var algorithm = reader["Algo"].ToString();

                                // Use PasswordHasher to verify the entered password against the stored hashed password
                                var passwordHasher = new PasswordHasher<object>();
                                var hashedPassword = HashPassword(loginRequest.Password, salt, algorithm);

                                var result = passwordHasher.VerifyHashedPassword(null, storedPassword, hashedPassword);

                                if (result == PasswordVerificationResult.Success)
                                {
                                    // Passwords match, user is authenticated
                                    var userData = new UserData
                                    {
                                        EmpCode = reader["EmpCode"].ToString(),
                                        Status = reader["isactive"].ToString()
                                    };

                                    // Continue with the rest of your code

                                    var response = new LoginResponse
                                    {
                                        IsSuccessful = true,
                                        Message = "Login successful",
                                        UserData = userData
                                    };

                                    return Ok(response);
                                }
                            }
                        }
                    }

                    // Authentication failed
                    var failedResponse = new LoginResponse
                    {
                        IsSuccessful = false,
                        Message = "Invalid credentials",
                        UserData = null
                    };

                    return Unauthorized(failedResponse);
                }
            }
            catch (Exception ex)
            {
                // Log the exception or handle it appropriately
                return StatusCode(500, $"An error occurred: {ex.Message}");
            }
        }

        private string HashPassword(string password, string salt, string algorithm)
        {
            try
            {
                // Ensure input parameters are not null or empty
                if (string.IsNullOrEmpty(password) || string.IsNullOrEmpty(salt) || string.IsNullOrEmpty(algorithm))
                {
                    // Handle the case where input parameters are invalid
                    throw new ArgumentException("Invalid input parameters for password hashing.");
                }

                // Normalize the salt
                salt = NormalizeBase64String(salt);

                byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
                byte[] saltBytes = Convert.FromBase64String(salt);

                using (var hasher = new HMACSHA256(saltBytes))
                {
                    var hashedBytes = hasher.ComputeHash(passwordBytes);
                    return Convert.ToBase64String(hashedBytes);
                }
            }
            catch (Exception ex)
            {
                // Log the exception or handle it appropriately
                Console.WriteLine($"An error occurred during password hashing: {ex.Message}");
                throw; // Rethrow the exception or handle it based on your application's requirements
            }
        }

        private string NormalizeBase64String(string base64String)
        {
            try
            {
                // Trim any whitespace characters from the string
                base64String = base64String.Trim();

                // Add padding if needed
                while (base64String.Length % 4 != 0)
                {
                    base64String += "=";
                }

                // Verify if the string is a valid Base64 string
                Convert.FromBase64String(base64String);

                return base64String;
            }
            catch (FormatException)
            {
                // Handle the case where the input is not a valid Base64 string
                throw new FormatException("The input is not a valid Base-64 string.");
            }
        }



    }
}