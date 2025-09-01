using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using System.Data;
using MySql.Data.MySqlClient;
using System.Text.RegularExpressions;
using System.Net;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddSingleton<AuthService>();
var app = builder.Build();

app.MapGet("/", () => "Hello World!");

// Secure input validation function
string SanitizeInput(string input)
{
    if (string.IsNullOrWhiteSpace(input)) return string.Empty;
    // Remove script tags and encode special characters
    input = Regex.Replace(input, "<.*?>", string.Empty);
    input = input.Replace("'", "").Replace("\"", "");
    input = Regex.Replace(input, @"[;--]", string.Empty); // Remove SQL meta-characters
    return input.Trim();
}

bool IsValidEmail(string email)
{
    return Regex.IsMatch(email, @"^[^@\s]+@[^@\s]+\.[^@\s]+$");
}

app.MapPost("/submit", async (HttpContext context) =>
{
    var form = await context.Request.ReadFormAsync();
    var username = SanitizeInput(form["username"]);
    var email = SanitizeInput(form["email"]);

    if (username.Length > 100)
        return Results.BadRequest("Username too long");
    if (!IsValidEmail(email))
        return Results.BadRequest("Invalid email");

    // Parameterized query to prevent SQL injection
    using var conn = new MySqlConnection("Server=localhost;Database=safevault;Uid=root;Pwd=yourpassword;");
    await conn.OpenAsync();
    using var cmd = new MySqlCommand("INSERT INTO Users (Username, Email) VALUES (@username, @email)", conn);
    cmd.Parameters.AddWithValue("@username", username);
    cmd.Parameters.AddWithValue("@email", email);
    await cmd.ExecuteNonQueryAsync();

    // Output encoding for future HTML rendering
    var safeUsername = WebUtility.HtmlEncode(username);

    return Results.Ok($"User '{safeUsername}' submitted successfully");
});

// Authentication endpoint
app.MapPost("/login", async (HttpContext context, AuthService authService) =>
{
    var form = await context.Request.ReadFormAsync();
    var username = form["username"];
    var password = form["password"];
    var user = authService.Authenticate(username, password);
    if (user == null)
        return Results.Unauthorized();
    return Results.Ok(new { user.Username, user.Role });
});

// Admin dashboard (role-based authorization)
app.MapGet("/admin", (HttpContext context) =>
{
    var username = context.Request.Query["username"];
    var user = AuthService.Users.Find(u => u.Username == username);
    if (user == null || user.Role != "admin")
        return Results.Forbid();
    return Results.Ok("Welcome to the Admin Dashboard!");
});

app.Run();

public partial class Program { }