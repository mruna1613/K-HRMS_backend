using backend.Entities;
using backend.Models.Controllers;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Linq;
using System.Threading.Tasks;
using backend.Models;


[ApiController]
[Route("api/[controller]")]
public class LoginController : ControllerBase
{
    private readonly LoginDbContext _dbContext;

    public LoginController(LoginDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    [HttpPost]
    public async Task<IActionResult> Login([FromBody] LoginRequest loginRequest)
    {
        if (loginRequest == null || string.IsNullOrEmpty(loginRequest.EmpCode) || string.IsNullOrEmpty(loginRequest.Password))
        {
            return BadRequest("Invalid request");
        }

        try
        {
            var empCreds = await _dbContext.EmpCreds
                .Where(e => e.EmpCode == int.Parse(loginRequest.EmpCode))
                .FirstOrDefaultAsync();

            if (empCreds != null)
            {
                // Check password logic, compare hashed password with user input
                if (Protector.PasswordMatch(loginRequest.Password, empCreds.Password, empCreds.Salt, (short)empCreds.Algo))
                {
                    // Authentication successful, return appropriate response
                    var userData = new UserData
                    {
                        EmpCode = empCreds.EmpCode.ToString(),
                        // Include other user data as needed
                    };

                    var response = new LoginResponse
                    {
                        IsSuccessful = true,
                        Message = "Login successful",
                        UserData = userData
                    };

                    return Ok(response);
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
        catch (Exception ex)
        {
            // Log the exception or handle it appropriately
            return StatusCode(500, "Internal server error");
        }
    }
}