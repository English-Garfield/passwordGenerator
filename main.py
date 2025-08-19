import math
import secrets
import string
import argparse
import json
import sys
from typing import List, Dict, Any

from sklearn.metrics.cluster import entropy


class passwordGenerator:

    def __init__(self):
        self.charSets = {
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
        args:
            length: Password length (4-128)
            use_uppercase: Include uppercase letters
            use_lowercase: Include lowercase letters
            use_numbers: Include numbers
            use_symbols: Include symbols
            exclude_ambiguous: Exclude ambiguous characters (0, O, l, I, etc.)
        """

        if length < 4 or length > 128:
            raise ValueError("Password length must be between 4 and 128 characters")

        # char pool build
        charPool = ''
        requiredChars = []

        charSets = self.charSets.copy()

        # remove ambig chars
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

        # Gen Pw w/ diversity
        passwordChars = requiredChars[:]

        # remaining chars
        remainingLength = length - len(requiredChars)
        for i in range(remainingLength):
            passwordChars.append(secrets.choice(charPool))

        # shuffle chars
        for i in range(len(passwordChars) - 1, 0, -1):
            j = secrets.randbelow(i + 1)
            passwordChars[i], passwordChars[j] = passwordChars[j], passwordChars[i]

        return ''.join(passwordChars)

    def calculateEntropy(self, password: str) -> float:
        charSpace = 0

        if any(c.isupper() for c in password):
            charSpace += 26
        if any(c.islower() for c in password):
            charSpace += 26
        if any(c.isdigit() for c in password):
            charSpace += 10
        if any(c in self.charSets['symbols'] for c in password):
            charSpace += len(self.charSets['symbols'])

        if charSpace == 0:
            return 0.0

        return len(password) * math.log2(charSpace)

    def assessStrength(self, password: str) -> Dict[str, Any]:
        e = self.calculateEntropy(password)
        length = len(password)

        # Entropy-based strength
        if e >= 80:
            strength = 'Very Strong'
            score = 100
        elif e >= 60:
            strength = 'Strong'
            score = 80
        elif e >= 40:
            strength = 'Moderate'
            score = 60
        elif e >= 20:
            strength = 'Weak'
            score = 40
        else:
            strength = 'Very Weak'
            score = 20

        hasUpper = any(c.isupper() for c in password)
        hasLower = any(c.islower() for c in password)
        hasNumber = any(c.isdigit() for c in password)
        hasSymbol = any(c in self.charSets['symbols'] for c in password)

        charTypes = sum([hasUpper, hasLower, hasNumber, hasSymbol])

        return {
            'strength': strength,
            'score': score,
            'entropy': round(e, 2),
            'length': length,
            'charTypes': charTypes,
            'hasUpper': hasUpper,
            'hasLower': hasLower,
            'hasNumber': hasNumber,
            'hasSymbol': hasSymbol
        }

    def generateMultiple(self):
        pass


def main():
    pass


if __name__ == "__main__":
    main()
