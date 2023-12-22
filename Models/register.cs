using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Data.SqlClient;
using System;
using System.Linq;
using System.Threading.Tasks;
using System.Data;
using Microsoft.AspNetCore.Identity;

namespace backend.Models
{
    [ApiController]
    [Route("[controller]")]
    public class RegistrationController : ControllerBase
    {
        private readonly IConfiguration _configuration;

        public RegistrationController(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        [HttpPost("/register")]
        public async Task<IActionResult> Register([FromBody] RegistrationRequest request)
        {
            try
            {
                var empCode = request.EmpCode;
                var password = request.Password;
                var name = request.Name;
                var email = request.Email;

                // Check if the user already exists in the users table
                var existingUser = GetUser(empCode);

                if (existingUser != null)
                {
                    // User already exists, handle accordingly (e.g., return an error)
                    return BadRequest("User already registered.");
                }

                // Generate a new registration key
                var newRegistrationKey = GenerateRandomKey(10);

                // Hash the user's password
                var hashedPassword = HashPassword(password);

                // Store the new user details in the users table
                using (var connection = new SqlConnection(_configuration.GetConnectionString("DefaultConnection")))
                {
                    await connection.OpenAsync();

                    using (var cmd = new SqlCommand("INSERT INTO [hrms_app].[ecohrms].[users] ([EmpCode], [Name], [Email], [CreatedOn], [ModifiedOn], [IsEnabled]) VALUES (@empCode, @name, @email, GETDATE(), GETDATE(), 1)", connection))
                    {
                        cmd.Parameters.AddWithValue("@empCode", empCode);
                        cmd.Parameters.AddWithValue("@name", name);
                        cmd.Parameters.AddWithValue("@email", email);

                        await cmd.ExecuteNonQueryAsync();
                    }

                    // Store the new registration key, hashed password, and loginattempts in the empCreds table
                    using (var empCredsCmd = new SqlCommand("INSERT INTO [hrms_app].[dbo].[empCreds] ([EmpCode], [Password], [Salt], [Algo], [loginattempts], [CreatedOn], [ModifiedOn], [isactive]) VALUES (@empCode, @password, @salt, @algo, @loginattempts, @createdOn, @modifiedOn, @isActive)", connection))
                    {
                        empCredsCmd.Parameters.AddWithValue("@empCode", empCode);
                        empCredsCmd.Parameters.AddWithValue("@password", hashedPassword);
                        empCredsCmd.Parameters.AddWithValue("@salt", "GeneratedSalt"); // You should generate and store a unique salt for each user

                        // Use SqlDbType.Int for @algo parameter
                        empCredsCmd.Parameters.Add("@algo", SqlDbType.Int).Value = GetHashingAlgorithmValue("HashingAlgorithm");

                        // Set a default value for loginattempts (0 in this case)
                        empCredsCmd.Parameters.AddWithValue("@loginattempts", 0);

                        // Set the current date and time for CreatedOn
                        empCredsCmd.Parameters.AddWithValue("@createdOn", DateTime.Now);

                        // Set the current date and time for ModifiedOn
                        empCredsCmd.Parameters.AddWithValue("@modifiedOn", DateTime.Now);

                        // Set a default value for isactive (assuming 'R' represents an active state)
                        empCredsCmd.Parameters.AddWithValue("@isActive", "R"); // Assuming 'isactive' is of type CHAR or VARCHAR

                        await empCredsCmd.ExecuteNonQueryAsync();
                    }
                }

                // Send the registration key as a JSON response
                return Ok(new { RegistrationKey = newRegistrationKey });
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"An error occurred: {ex.Message}");
                Console.Error.WriteLine($"Stack Trace: {ex.StackTrace}");
                return StatusCode(500, $"An error occurred: {ex.Message}");
            }
        }

        private string GenerateRandomKey(int length)
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            var random = new Random();

            return new string(Enumerable.Repeat(chars, length)
                .Select(s => s[random.Next(s.Length)]).ToArray());
        }

        private UserCredentials GetUser(string empCode)
        {
            // Implement the logic to retrieve user details from the users table
            using (var connection = new SqlConnection(_configuration.GetConnectionString("DefaultConnection")))
            {
                connection.Open();
                string query = "SELECT * FROM [hrms_app].[ecohrms].[users] WHERE [EmpCode] = @EmpCode";
                using (var cmd = new SqlCommand(query, connection))
                {
                    cmd.Parameters.AddWithValue("@EmpCode", empCode);

                    using (var reader = cmd.ExecuteReader())
                    {
                        if (reader.Read())
                        {
                            return new UserCredentials
                            {
                                EmpCode = reader["EmpCode"].ToString(),
                                Name = reader["Name"].ToString(),
                                Email = reader["Email"].ToString(),
                                // Add other fields as needed
                            };
                        }
                    }
                }
            }

            return null;
        }

        private string HashPassword(string password)
        {
            // Use a secure password hashing algorithm like Argon2 or bcrypt
            var passwordHasher = new PasswordHasher<object>();
            var hashedPassword = passwordHasher.HashPassword(null, password);
            return hashedPassword;
        }

        private int GetHashingAlgorithmValue(string algo)
        {
            // Your logic to map algorithm names to integer values
            // For example, you can use a switch statement or a lookup table
            // Return the appropriate integer value for the specified algorithm
            return 1; // Placeholder value, replace it with your logic
        }

        public class UserCredentials
        {
            public string? EmpCode { get; set; }
            public string? Name { get; set; }
            public string? Email { get; set; }
            // Add other user-related properties as needed
        }

        public class RegistrationRequest
        {
            public string? EmpCode { get; set; }
            public string? Name { get; set; }
            public string? Email { get; set; }
            public string? Password { get; set; }
        }
    }
}