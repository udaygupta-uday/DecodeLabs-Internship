# DecodeLabs-Internship
Project : 1
Password Strength Checker
Features:
Menu-driven program
Checks password type(Weak,Medium,Strong)
Time complexity:0(n)(linear scan over the password)


🔐 Password Strength Checker (Project 1)

📖 Overview

This project is a Password Strength Checker built in Python as part of my cybersecurity learning journey. It evaluates a user's password and classifies it as Weak, Medium, or Strong based on common password security rules.

The program also provides suggestions to help users create stronger passwords.

---

✨ Features

- Checks password length
- Detects uppercase and lowercase letters
- Detects numbers
- Detects special symbols
- Identifies common weak passwords using "hmac.compare_digest()"
- Classifies passwords as Weak, Medium, or Strong
- Provides recommendations for improving weak or medium passwords
- Menu-driven interface for easy interaction

---

🧠 Algorithm

1. Read the password entered by the user.
2. Compare it with a list of common weak passwords using "hmac.compare_digest()".
3. Scan the password once to check for:
   - Uppercase letters
   - Lowercase letters
   - Digits
   - Special symbols
4. Measure the password length.
5. Apply the following rules:
   - Weak
     - Password is found in the common password list, or
     - Does not satisfy minimum security requirements.
   - Medium
     - At least 8 characters long.
     - Contains lowercase letters and numbers.
   - Strong
     - At least 12 characters long.
     - Contains uppercase letters, lowercase letters, numbers, and special symbols.
6. Display the password strength.
7. If the password is not strong, provide suggestions to improve it.

---

⚙️ Time Complexity

- Time Complexity: O(n)

The password is scanned linearly using Python's "any()" function to detect different character types.

- Space Complexity: O(1)

Only a fixed amount of extra memory is used.

---

▶️ How to Run

1. Clone the repository.
2. Ensure Python 3 is installed.
3. Run the program:

python password_strength_checker.py

4. Choose one of the following options:

- Check Password Strength
- Show Password Analysis
- Exit

---

💻 Example Output

Enter Password: hello123

Password Analysis
-------------------------
Length           : 8
Uppercase        : False
Lowercase        : True
Digit            : True
Special Symbol   : False
Strength         : Medium

Suggestions to make your password stronger:
- Use at least 12 characters.
- Add at least one uppercase letter (A-Z).
- Add at least one special symbol (!, @, #, $, %, etc.).

Example of a strong password:
Secure@2026Tech,Name@143Verify

---

🔒 Security Notes

- Uses "hmac.compare_digest()" for comparing passwords against a small list of known weak passwords.
- Encourages users to create stronger passwords before password hashing.
- This project focuses on password validation, not password storage or authentication.

---

⚠️ Limitations

- Uses a small built-in list of common weak passwords instead of a comprehensive password database.
- Does not calculate password entropy.
- Does not detect dictionary words beyond the predefined list.
- Does not check whether the password has appeared in known data breaches.
- Does not hash or store passwords.
- Intended as an educational project rather than a production-ready password validator.

---

🚀 Future Improvements

- Estimate password entropy.
- Integrate a larger database of weak passwords.
- Check passwords against publicly known breached password datasets.
- Generate secure password suggestions.
- Build a graphical user interface (GUI).
- Add support for password history and policy customization.

---

📚 Concepts Used

- Python Functions
- Conditional Statements
- Loops
- String Handling
- "any()" Function
- "hmac.compare_digest()"
- Time Complexity Analysis (O(n))
- Menu-Driven Programming
- Cybersecurity Fundamentals

---

🎯 Learning Outcome

This project helped me understand:

- Password security principles
- Secure password validation techniques
- Python programming fundamentals
- Writing modular and reusable code
- Applying cybersecurity concepts to practical projects

---

👨‍💻 Author

Uday Narayan Gupta

Project 1 – Password Strength Checker

This is my first cybersecurity project, and I'm excited to continue building practical security tools while learning more about Python and cybersecurity.
