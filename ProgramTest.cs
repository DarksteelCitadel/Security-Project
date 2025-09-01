using NUnit.Framework;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc.Testing;

namespace SecurityApplication.Tests
{
    [TestFixture]
    public class ProgramTests
    {
        private WebApplicationFactory<Program> _factory;
        private HttpClient _client;

        [SetUp]
        public void Setup()
        {
            _factory = new WebApplicationFactory<Program>();
            _client = _factory.CreateClient();
        }

        [TearDown]
        public void TearDown()
        {
            _client.Dispose();
            _factory.Dispose();
        }

        [Test]
        public async Task RootEndpoint_ReturnsHelloWorld()
        {
            var response = await _client.GetAsync("/");
            response.EnsureSuccessStatusCode();
            var content = await response.Content.ReadAsStringAsync();
            Assert.AreEqual("Hello World!", content);
        }

        [Test]
        public async Task SubmitEndpoint_RejectsSQLInjection()
        {
            var maliciousUsername = "admin'; DROP TABLE Users;--";
            var maliciousEmail = "test@example.com";
            var content = new StringContent($"username={maliciousUsername}&email={maliciousEmail}", Encoding.UTF8, "application/x-www-form-urlencoded");
            var response = await _client.PostAsync("/submit", content);
            response.EnsureSuccessStatusCode();
            var responseBody = await response.Content.ReadAsStringAsync();
            Assert.IsFalse(responseBody.Contains("DROP TABLE"), "SQL Injection payload should not be executed.");
        }

        [Test]
        public async Task SubmitEndpoint_RejectsXSS()
        {
            var maliciousUsername = "<script>alert('xss')</script>";
            var maliciousEmail = "xss@example.com";
            var content = new StringContent($"username={maliciousUsername}&email={maliciousEmail}", Encoding.UTF8, "application/x-www-form-urlencoded");
            var response = await _client.PostAsync("/submit", content);
            response.EnsureSuccessStatusCode();
            var responseBody = await response.Content.ReadAsStringAsync();
            Assert.IsFalse(responseBody.Contains("<script>"), "XSS payload should not be reflected in response.");
        }

        [Test]
        public async Task SubmitEndpoint_ValidatesEmailFormat()
        {
            var invalidEmail = "not-an-email";
            var content = new StringContent($"username=validuser&email={invalidEmail}", Encoding.UTF8, "application/x-www-form-urlencoded");
            var response = await _client.PostAsync("/submit", content);
            var responseBody = await response.Content.ReadAsStringAsync();
            Assert.IsTrue(responseBody.Contains("Invalid email"), "Invalid email format should be rejected.");
        }

        [Test]
        public async Task SubmitEndpoint_ValidatesUsernameLength()
        {
            var longUsername = new string('a', 101); // Exceeds VARCHAR(100)
            var content = new StringContent($"username={longUsername}&email=test@example.com", Encoding.UTF8, "application/x-www-form-urlencoded");
            var response = await _client.PostAsync("/submit", content);
            var responseBody = await response.Content.ReadAsStringAsync();
            Assert.IsTrue(responseBody.Contains("Username too long"), "Username exceeding max length should be rejected.");
        }

        [Test]
        public async Task SubmitEndpoint_BlocksSQLInjectionAttempt()
        {
            var maliciousUsername = "test'; DROP TABLE Users;--";
            var content = new StringContent($"username={maliciousUsername}&email=test@example.com", Encoding.UTF8, "application/x-www-form-urlencoded");
            var response = await _client.PostAsync("/submit", content);
            response.EnsureSuccessStatusCode();
            var responseBody = await response.Content.ReadAsStringAsync();
            Assert.IsFalse(responseBody.Contains("DROP TABLE"), "SQL Injection should not be executed.");
        }

        [Test]
        public async Task SubmitEndpoint_BlocksXSSAttempt()
        {
            var maliciousUsername = "<img src=x onerror=alert('xss')>";
            var content = new StringContent($"username={maliciousUsername}&email=xss@example.com", Encoding.UTF8, "application/x-www-form-urlencoded");
            var response = await _client.PostAsync("/submit", content);
            response.EnsureSuccessStatusCode();
            var responseBody = await response.Content.ReadAsStringAsync();
            Assert.IsFalse(responseBody.Contains("<img"), "XSS payload should not be reflected.");
        }

    }
}