using System.Collections.Generic;
using BCrypt.Net;

public class User
{
    public string Username { get; set; }
    public string PasswordHash { get; set; }
    public string Role { get; set; }
}

public class AuthService
{
    public static readonly List<User> Users = new List<User>
    {
        new User { Username = "admin", PasswordHash = BCrypt.Net.BCrypt.HashPassword("adminpass"), Role = "admin" },
        new User { Username = "user", PasswordHash = BCrypt.Net.BCrypt.HashPassword("userpass"), Role = "user" }
    };

    public User Authenticate(string username, string password)
    {
        var user = Users.Find(u => u.Username == username);
        if (user != null && BCrypt.Net.BCrypt.Verify(password, user.PasswordHash))
        {
            return user;
        }
        return null;
    }
}