import hmac
import string
#Common weak passwords
COMMON_WEAK_PASSWORDS=["password","123456","123456789","qwerty","admin","welcome","abc123","password123"]

def is_common_password(password):
    for weak in COMMON_WEAK_PASSWORDS:
        if hmac.compare_digest(password,weak):
            return True
    return False
    
def check_password_strength(password):
    length=len(password)
    has_upper=any(ch.isupper() for ch in password )
    has_lower=any(ch.islower() for ch in password )
    has_digit=any(ch.isdigit() for ch in password )
    has_symbol=any(ch in string.punctuation for ch in password)
    
    if is_common_password(password):
        return "Weak"
    if length>=12 and has_upper and has_lower and has_digit and has_symbol:
        return "Strong"
    elif length>=8 and has_lower and has_digit:
        return "Medium"
    else:
        return "Weak"

def display_requirements(password):
    has_upper=any(ch.isupper() for ch in password)
    has_lower=any(ch.islower() for ch in password )
    has_digit=any(ch.isdigit() for ch in password )
    has_symbol=any(ch in string.punctuation for ch in password)
    
    strength=check_password_strength(password)

    print("\nPassword Analysis")
    print("---------------------------------")
    print("Length           :",len(password))
    print("Uppercase        :",has_upper)
    print("Lowercase        :",has_lower)
    print("Digit            :",has_digit)
    print("Special Symbol   :",has_symbol)
    print("Strength         :",strength)
    
    if strength != "Strong":
        print("\nSuggestions to make your password stronger:")
        if len(password) < 12:
            print("- Use at least 12 characters.")
        if not has_upper:
            print("- Add at least one uppercase letter(A-Z).")
        if not has_lower:
            print("- Add at least one lowercase letter(a-z).")
        if not has_digit:
            print("_ add at least one digit(0-9).")
        if not has_symbol:
            print("- Add at least one special symbol(!,@,#,$,%,etc.).")
        
        print("\nExample of a strong password:")
        print("Secure@2026Tech,Name@143Verify")
    else:print("\n Excellent! Your password is strong.")

def menu():
    while True:
        print("\n========= Password Strength Checker =========")
        print("1. Check Password Strength")
        print("2.Show Password Analysis")
        print("3.Exit")
        choice=input("Enter your choice(1-3): ")
        if choice =="1":
            password=input("Enter Password: ")
            print("Password Strength:",check_password_strength(password))

        elif choice =="2":
            password=input("Enter Password: ")
            display_requirements(password)

        elif choice =="3":
            print("Thank you for using Password Strength Checker.")

        else:
            print("Invalid choice! Please enter 1,2,3.")

if __name__== "__main__":
    menu()