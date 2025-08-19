import secrets
import string
import argparse
import json
import sys
from typing import List, Dict, Any


class passwordGenerator:

    def __init__(self):
        self.char_sets = {
            'uppercase': string.ascii_uppercase,
            'lowercase': string.ascii_lowercase,
            'numbers': string.digits,
            'symbols': '!@#$%^&*()_+-=[]{}|;:,.<>?'
        }

    def generatePassword(self,
                         length: int = 16,
                         useUppercase: bool = True,
                         useLowercase: bool = True,
                         useNumbers: bool = True,
                         useSymbols: bool = True,
                         excludeAmbiguous: bool = False) -> str:
        """
        Args:
            length: Password length (4-128)
            useUppercase: Include uppercase letters
            useLowercase: Include lowercase letters
            useNumbers: Include numbers
            useSymbols: Include symbols
            excludeAmbiguous: Exclude ambiguous characters (0, O, l, I, etc.)
        """

        if length < 4 or length > 128:
            raise ValueError("Password length must be between 4 and 128 characters")

        # char pool
        charPool = ''
        requiredChars = []

        charSets = self.char_sets.copy()

        # Remove ambig chars
        if excludeAmbiguous:
            ambiguous = '0O1lI|`'
            for key in charSets:
                charSets[key] = ''.join(c for c in charSets[key] if c not in ambiguous)

        if useUppercase:
            charPool += charSets['uppercase']
            requiredChars.append(secrets.choice(charSets['uppercase']))

        if useLowercase:
            charPool += charSets['lowercase']
            requiredChars.append(secrets.choice(charSets['lowercase']))

        if useNumbers:
            charPool += charSets['numbers']
            requiredChars.append(secrets.choice(charSets['numbers']))

        if useSymbols:
            charPool += charSets['symbols']
            requiredChars.append(secrets.choice(charSets['symbols']))

        if not charPool:
            raise ValueError("At least one character type must be selected")

        # Gen pw w/ diversity
        passwordChars = requiredChars[:]

        # Random chars
        remainingLength = length - len(requiredChars)
        for _ in range(remainingLength):
            passwordChars.append(secrets.choice(charPool))

        # Shuffle pw
        for i in range(len(passwordChars) - 1, 0, -1):
            j = secrets.randbelow(i + 1)
            passwordChars[i], passwordChars[j] = passwordChars[j], passwordChars[i]

        return ''.join(passwordChars)

    def calculateEntropy(self, password: str) -> float:
        """Entropy in bits"""
        charSpace = 0

        if any(c.isupper() for c in password):
            charSpace += 26
        if any(c.islower() for c in password):
            charSpace += 26
        if any(c.isdigit() for c in password):
            charSpace += 10
        if any(c in self.char_sets['symbols'] for c in password):
            charSpace += len(self.char_sets['symbols'])

        if charSpace == 0:
            return 0.0

        import math
        return len(password) * math.log2(charSpace)

    def assessStrength(self, password: str) -> Dict[str, Any]:
        e = self.calculateEntropy(password) # Entropy
        length = len(password)

        # Strength categories based on entropy
        if e >= 80:
            strength = "Very Strong"
            score = 100
        elif e >= 60:
            strength = "Strong"
            score = 80
        elif e >= 40:
            strength = "Moderate"
            score = 60
        elif e >= 25:
            strength = "Weak"
            score = 40
        else:
            strength = "Very Weak"
            score = 20

        # Character type analysis
        hasUpper = any(c.isupper() for c in password)
        hasLower = any(c.islower() for c in password)
        hasDigits = any(c.isdigit() for c in password)
        hasSymbols = any(c in self.char_sets['symbols'] for c in password)

        charTypes = sum([hasUpper, hasLower, hasDigits, hasSymbols])

        return {
            'strength': strength,
            'score': score,
            'entropy': round(e, 2),
            'length': length,
            'character_types': charTypes,
            'has_uppercase': hasUpper,
            'has_lowercase': hasLower,
            'has_numbers': hasDigits,
            'has_symbols': hasSymbols
        }

    def generateMultiple(self, count: int = 5, **kwargs) -> List[str]:
        return [self.generatePassword(**kwargs) for _ in range(count)]


def interactive_mode():
    generator = passwordGenerator()

    print("=" * 50)
    print("    SECURE PASSWORD GENERATOR")
    print("=" * 50)
    print()

    while True:
        try:
            # Get password length
            while True:
                try:
                    length_input = input("Password length (4-128) [16]: ").strip()
                    if not length_input:
                        length = 16
                        break
                    length = int(length_input)
                    if 4 <= length <= 128:
                        break
                    else:
                        print("Length must be between 4 and 128")
                except ValueError:
                    print("Please enter a valid number")

            # Get character type preferences
            print("\nCharacter types to include:")

            def get_yes_no(prompt, default=True):
                while True:
                    default_str = "Y/n" if default else "y/N"
                    response = input(f"{prompt} [{default_str}]: ").strip().lower()
                    if not response:
                        return default
                    if response in ['y', 'yes', '1', 'true']:
                        return True
                    elif response in ['n', 'no', '0', 'false']:
                        return False
                    else:
                        print("Please enter y/n")

            useUppercase = get_yes_no("  Include uppercase letters (A-Z)?", True)
            useLowercase = get_yes_no("  Include lowercase letters (a-z)?", True)
            useNumbers = get_yes_no("  Include numbers (0-9)?", True)
            useSymbols = get_yes_no("  Include symbols (!@#$%^&*)?", True)

            # Check if at least one character type is selected
            if not any([useUppercase, useLowercase, useNumbers, useSymbols]):
                print("You must select at least one character type!")
                continue

            # Additional options
            print("\nAdditional options:")
            excludeAmbiguous = get_yes_no("  Exclude ambiguous characters (0, O, l, I)?", False)

            # Number of passwords
            while True:
                try:
                    count_input = input("\nHow many passwords to generate? [1]: ").strip()
                    if not count_input:
                        count = 1
                        break
                    count = int(count_input)
                    if count > 0:
                        break
                    else:
                        print("Count must be greater than 0")
                except ValueError:
                    print("Please enter a valid number")

            # Generate passwords
            print("\n" + "=" * 53)
            print(" Generating passwords...")
            print("=" * 53)

            passwords = generator.generateMultiple(
                count=count,
                length=length,
                useUppercase=useUppercase,
                useLowercase=useLowercase,
                useNumbers=useNumbers,
                useSymbols=useSymbols,
                excludeAmbiguous=excludeAmbiguous
            )

            # Display results
            for i, password in enumerate(passwords, 1):
                if count > 1:
                    print(f"\n Password {i}:")
                else:
                    print(f"\n Generated Password:")

                print(f"   {password}")

                # Show strength analysis
                analysis = generator.assessStrength(password)
                strength_emoji = {
                    "Very Strong": "🟢",
                    "Strong": "🟢",
                    "Moderate": "🟡",
                    "Weak": "🟠",
                    "Very Weak": "🔴"
                }

                emoji = strength_emoji.get(analysis['strength'], "⚪")
                print(f"   {emoji} Strength: {analysis['strength']} ({analysis['entropy']} bits entropy)")
                print(f"    Character types: {analysis['character_types']}/4")

                if analysis['entropy'] < 40:
                    print(f"   ️  Consider using a longer password or more character types")

            # Ask what to do next
            print("\n" + "=" * 53)

            while True:
                choice = input("\nWhat would you like to do?\n"
                               "  [G] Generate more passwords\n"
                               "  [C] Copy last password to clipboard (if available)\n"
                               "  [S] Save passwords to file\n"
                               "  [Q] Quit\n"
                               "Choice: ").strip().lower()

                if choice in ['g', 'generate', '']:
                    break
                elif choice in ['c', 'copy']:
                    try:
                        import subprocess
                        if passwords:
                            # Try to copy to clipboard (works on macOS and some Linux)
                            try:
                                subprocess.run(['pbcopy'], input=passwords[-1], text=True, check=True)
                                print("Password copied to clipboard!")
                            except (subprocess.CalledProcessError, FileNotFoundError):
                                try:
                                    subprocess.run(['xclip', '-selection', 'clipboard'],
                                                   input=passwords[-1], text=True, check=True)
                                    print("Password copied to clipboard!")
                                except (subprocess.CalledProcessError, FileNotFoundError):
                                    print("Clipboard not available. Password:")
                                    print(f"   {passwords[-1]}")
                    except Exception as e:
                        print(f"Could not copy to clipboard: {e}")
                        if passwords:
                            print(f"Password: {passwords[-1]}")
                elif choice in ['s', 'save']:
                    filename = input("Enter filename [passwords.txt]: ").strip()
                    if not filename:
                        filename = "passwords.txt"

                    try:
                        with open(filename, 'w') as f:
                            f.write("Secure Password Generator - Generated Passwords\n")
                            f.write("=" * 50 + "\n\n")
                            for i, password in enumerate(passwords, 1):
                                analysis = generator.assessStrength(password)
                                f.write(f"Password {i}: {password}\n")
                                f.write(f"Strength: {analysis['strength']} ({analysis['entropy']} bits)\n")
                                f.write(f"Character types: {analysis['character_types']}/4\n\n")

                        print(f"Passwords saved to {filename}")
                    except Exception as e:
                        print(f"Could not save file: {e}")
                elif choice in ['q', 'quit', 'exit']:
                    print("\nThanks for using Secure Password Generator!")
                    return
                else:
                    print("Please choose G, C, S, or Q")

        except KeyboardInterrupt:
            print("\n\nThanks for using Secure Password Generator!")
            return
        except Exception as e:
            print(f"\nAn error occurred: {e}")
            continue


def main():
    """Command line interface for the password generator."""
    parser = argparse.ArgumentParser(description="Secure Password Generator")
    parser.add_argument('-l', '--length', type=int, default=16,
                        help='Password length (4-128, default: 16)')
    parser.add_argument('-c', '--count', type=int, default=1,
                        help='Number of passwords to generate (default: 1)')
    parser.add_argument('--no-uppercase', action='store_true',
                        help='Exclude uppercase letters')
    parser.add_argument('--no-lowercase', action='store_true',
                        help='Exclude lowercase letters')
    parser.add_argument('--no-numbers', action='store_true',
                        help='Exclude numbers')
    parser.add_argument('--no-symbols', action='store_true',
                        help='Exclude symbols')
    parser.add_argument('--exclude-ambiguous', action='store_true',
                        help='Exclude ambiguous characters (0, O, l, I, etc.)')
    parser.add_argument('--analyze', action='store_true',
                        help='Show password strength analysis')
    parser.add_argument('--json', action='store_true',
                        help='Output in JSON format')
    parser.add_argument('-i', '--interactive', action='store_true',
                        help='Launch interactive mode')

    args = parser.parse_args()

    # Launch interactive mode if no arguments or -i flag
    if len(sys.argv) == 1 or args.interactive:
        interactive_mode()
        return

    generator = passwordGenerator()

    try:
        passwords = generator.generateMultiple(
            count=args.count,
            length=args.length,
            useUppercase=not args.no_uppercase,
            useLowercase=not args.no_lowercase,
            useNumbers=not args.no_numbers,
            useSymbols=not args.no_symbols,
            excludeAmbiguous=args.exclude_ambiguous
        )

        if args.json:
            output = []
            for password in passwords:
                data = {'password': password}
                if args.analyze:
                    data.update(generator.assessStrength(password))
                output.append(data)
            print(json.dumps(output, indent=2))
        else:
            for i, password in enumerate(passwords, 1):
                if args.count > 1:
                    print(f"Password {i}: {password}")
                else:
                    print(password)

                if args.analyze:
                    analysis = generator.assessStrength(password)
                    print(f"  Strength: {analysis['strength']}")
                    print(f"  Entropy: {analysis['entropy']} bits")
                    print(f"  Character types: {analysis['character_types']}/4")
                    print()

    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
