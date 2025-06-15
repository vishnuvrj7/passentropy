#!/usr/bin/env python3

import argparse
import math
import re
import sys
from collections import Counter
from typing import Dict, List, Tuple, Set
import getpass

class PasswordAnalyzer:
    def __init__(self):
        
        self.common_patterns = {
            'sequential': [
                'abcdefghijklmnopqrstuvwxyz',
                'qwertyuiopasdfghjklzxcvbnm',
                '1234567890'
            ],
            'keyboard_rows': [
                'qwertyuiop', 'asdfghjkl', 'zxcvbnm',
                '1234567890', '!@#$%^&*()'
            ],
            'repeated_chars': r'(.)\1{2,}',
            'common_substitutions': {
                'a': '@', 'e': '3', 'i': '1', 'o': '0', 's': '$', 't': '7'
            }
        }
        
        self.common_passwords = {
            'password', '123456', 'password123', 'admin', 'qwerty',
            'letmein', 'welcome', 'monkey', '1234567890', 'abc123'
        }
        
        self.char_sets = {
            'lowercase': set('abcdefghijklmnopqrstuvwxyz'),
            'uppercase': set('ABCDEFGHIJKLMNOPQRSTUVWXYZ'),
            'digits': set('0123456789'),
            'special': set('!@#$%^&*()_+-=[]{}|;:,.<>?')
        }

    def calculate_entropy(self, password: str) -> Tuple[float, int]:
        
        if not password:
            return 0.0, 0
        
        char_space = 0
        used_chars = set(password.lower())
        
        for char_set_name, char_set in self.char_sets.items():
            if used_chars & char_set:
                char_space += len(char_set)
        
        # Add any other characters not in standard sets
        other_chars = used_chars - set().union(*self.char_sets.values())
        char_space += len(other_chars)
        
        # Calculate entropy: log2(character_space^length)
        if char_space > 0:
            entropy = len(password) * math.log2(char_space)
        else:
            entropy = 0.0
            
        return entropy, char_space

    def detect_patterns(self, password: str) -> List[str]:
        """Detect common patterns in password."""
        patterns = []
        pw_lower = password.lower()
        
        # Check for sequential characters
        for seq in self.common_patterns['sequential']:
            for i in range(len(seq) - 2):
                if seq[i:i+3] in pw_lower or seq[i:i+3][::-1] in pw_lower:
                    patterns.append(f"Sequential characters: {seq[i:i+3]}")
        
        # Check for keyboard patterns
        for row in self.common_patterns['keyboard_rows']:
            for i in range(len(row) - 2):
                if row[i:i+3] in pw_lower:
                    patterns.append(f"Keyboard pattern: {row[i:i+3]}")
        
        # Check for repeated characters
        repeated = re.findall(self.common_patterns['repeated_chars'], password)
        if repeated:
            patterns.append(f"Repeated characters: {', '.join(set(repeated))}")
        
        # Check for common substitutions
        reversed_subs = {v: k for k, v in self.common_patterns['common_substitutions'].items()}
        for char in password:
            if char in reversed_subs:
                patterns.append(f"Common substitution: '{char}' for '{reversed_subs[char]}'")
        
        # Check for years (1900-2099)
        years = re.findall(r'(19|20)\d{2}', password)
        if years:
            patterns.append(f"Year pattern: {', '.join([''.join(year) for year in years])}")
        
        # Check for dates (basic MM/DD, DD/MM patterns)
        dates = re.findall(r'\d{1,2}[/-]\d{1,2}', password)
        if dates:
            patterns.append(f"Date pattern: {', '.join(dates)}")
        
        return patterns

    def check_common_passwords(self, password: str) -> bool:
        """Check if password is in common passwords list."""
        return password.lower() in self.common_passwords

    def calculate_character_diversity(self, password: str) -> Dict[str, int]:
        """Calculate character type diversity."""
        diversity = {
            'lowercase': 0,
            'uppercase': 0,
            'digits': 0,
            'special': 0,
            'unique_chars': 0
        }
        
        password_chars = set(password)
        diversity['unique_chars'] = len(password_chars)
        
        for char in password:
            if char.islower():
                diversity['lowercase'] += 1
            elif char.isupper():
                diversity['uppercase'] += 1
            elif char.isdigit():
                diversity['digits'] += 1
            else:
                diversity['special'] += 1
                
        return diversity

    def assess_strength(self, password: str) -> Dict:
        """Comprehensive password strength assessment."""
        if not password:
            return {
                'strength': 'Invalid',
                'score': 0,
                'entropy': 0.0,
                'issues': ['Empty password'],
                'recommendations': ['Enter a password']
            }
        
        # Basic metrics
        length = len(password)
        entropy, char_space = self.calculate_entropy(password)
        patterns = self.detect_patterns(password)
        is_common = self.check_common_passwords(password)
        diversity = self.calculate_character_diversity(password)
        
        # Scoring system (0-100)
        score = 0
        issues = []
        recommendations = []
        
        # Length scoring (0-25 points)
        if length >= 12:
            score += 25
        elif length >= 8:
            score += 15
        elif length >= 6:
            score += 10
        else:
            score += 5
            issues.append(f"Password too short ({length} characters)")
            recommendations.append("Use at least 12 characters")
        
        # Entropy scoring (0-30 points)
        if entropy >= 60:
            score += 30
        elif entropy >= 40:
            score += 20
        elif entropy >= 25:
            score += 15
        else:
            score += 5
            issues.append(f"Low entropy ({entropy:.1f} bits)")
            recommendations.append("Increase character variety and length")
        
        # Character diversity scoring (0-25 points)
        char_types = sum(1 for k, v in diversity.items() 
                        if k != 'unique_chars' and v > 0)
        if char_types >= 4:
            score += 25
        elif char_types >= 3:
            score += 18
        elif char_types >= 2:
            score += 12
        else:
            score += 5
            issues.append("Limited character variety")
            recommendations.append("Use uppercase, lowercase, digits, and special characters")
        
        # Pattern penalties (0-20 points deducted)
        pattern_penalty = min(len(patterns) * 5, 20)
        score -= pattern_penalty
        if patterns:
            issues.extend(patterns)
            recommendations.append("Avoid predictable patterns")
        
        # Common password check
        if is_common:
            score -= 30
            issues.append("Password is commonly used")
            recommendations.append("Use a unique, uncommon password")
        
        # Ensure score is within bounds
        score = max(0, min(100, score))
        
        # Determine strength category
        if score >= 80:
            strength = "Very Strong"
        elif score >= 60:
            strength = "Strong"
        elif score >= 40:
            strength = "Moderate"
        elif score >= 20:
            strength = "Weak"
        else:
            strength = "Very Weak"
        
        return {
            'strength': strength,
            'score': score,
            'length': length,
            'entropy': entropy,
            'char_space': char_space,
            'diversity': diversity,
            'patterns': patterns,
            'is_common': is_common,
            'issues': issues,
            'recommendations': recommendations
        }

    def generate_report(self, analysis: Dict) -> str:
        """Generate a detailed analysis report."""
        report = []
        report.append("=" * 60)
        report.append("PASSWORD STRENGTH ANALYSIS REPORT")
        report.append("=" * 60)
        
        # Overall assessment
        report.append(f"\nOVERALL STRENGTH: {analysis['strength']}")
        report.append(f"SECURITY SCORE: {analysis['score']}/100")
        
        # Technical details
        report.append(f"\nTECHNICAL DETAILS:")
        report.append(f"  Length: {analysis['length']} characters")
        report.append(f"  Entropy: {analysis['entropy']:.1f} bits")
        report.append(f"  Character Space: {analysis['char_space']}")
        
        # Character diversity
        div = analysis['diversity']
        report.append(f"\nCHARACTER COMPOSITION:")
        report.append(f"  Lowercase: {div['lowercase']}")
        report.append(f"  Uppercase: {div['uppercase']}")
        report.append(f"  Digits: {div['digits']}")
        report.append(f"  Special: {div['special']}")
        report.append(f"  Unique characters: {div['unique_chars']}")
        
        # Issues found
        if analysis['issues']:
            report.append(f"\nISSUES IDENTIFIED:")
            for i, issue in enumerate(analysis['issues'], 1):
                report.append(f"  {i}. {issue}")
        
        # Recommendations
        if analysis['recommendations']:
            report.append(f"\nRECOMMENDATIONS:")
            for i, rec in enumerate(analysis['recommendations'], 1):
                report.append(f"  {i}. {rec}")
        
        # Security notes
        report.append(f"\nSECURITY NOTES:")
        report.append(f"  - Entropy >50 bits: Resistant to offline attacks")
        report.append(f"  - Length >12 chars: Better against brute force")
        report.append(f"  - Mixed character types: Harder to crack")
        report.append(f"  - Avoid personal info and common patterns")
        
        report.append("=" * 60)
        return "\n".join(report)

def main():
    parser = argparse.ArgumentParser(
        description="Analyze password strength using entropy and pattern recognition",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          # Interactive mode (secure input)
  %(prog)s -p "MyPassword123"       # Direct password input
  %(prog)s -f passwords.txt         # Analyze passwords from file
  %(prog)s -q -p "test123"          # Quiet mode (score only)
        """
    )
    
    parser.add_argument('-p', '--password', 
                       help='Password to analyze (not recommended for security)')
    parser.add_argument('-f', '--file', 
                       help='File containing passwords to analyze (one per line)')
    parser.add_argument('-q', '--quiet', action='store_true',
                       help='Quiet mode - only show strength and score')
    parser.add_argument('--no-hide', action='store_true',
                       help='Don\'t hide password in output (security risk)')
    
    args = parser.parse_args()
    
    analyzer = PasswordAnalyzer()
    
    try:
        if args.file:
            # Analyze passwords from file
            try:
                with open(args.file, 'r') as f:
                    passwords = [line.strip() for line in f if line.strip()]
                
                for i, password in enumerate(passwords, 1):
                    if len(passwords) > 1:
                        print(f"\n--- Password {i} ---")
                    
                    analysis = analyzer.assess_strength(password)
                    
                    if args.quiet:
                        hidden_pw = "*" * len(password) if not args.no_hide else password
                        print(f"Password: {hidden_pw} | Strength: {analysis['strength']} | Score: {analysis['score']}/100")
                    else:
                        if not args.no_hide:
                            print(f"Password: {'*' * len(password)}")
                        print(analyzer.generate_report(analysis))
                        
            except FileNotFoundError:
                print(f"Error: File '{args.file}' not found.", file=sys.stderr)
                sys.exit(1)
            except Exception as e:
                print(f"Error reading file: {e}", file=sys.stderr)
                sys.exit(1)
                
        elif args.password:
            # Analyze single password from command line
            analysis = analyzer.assess_strength(args.password)
            
            if args.quiet:
                hidden_pw = "*" * len(args.password) if not args.no_hide else args.password
                print(f"Password: {hidden_pw} | Strength: {analysis['strength']} | Score: {analysis['score']}/100")
            else:
                if not args.no_hide:
                    print(f"Password: {'*' * len(args.password)}")
                print(analyzer.generate_report(analysis))
                
        else:
            # Interactive mode (secure)
            print("Password Strength Analyzer")
            print("Enter password (input will be hidden for security):")
            password = getpass.getpass("Password: ")
            
            if not password:
                print("No password entered. Exiting.")
                sys.exit(0)
            
            analysis = analyzer.assess_strength(password)
            
            if args.quiet:
                print(f"Strength: {analysis['strength']} | Score: {analysis['score']}/100")
            else:
                print(analyzer.generate_report(analysis))
                
    except KeyboardInterrupt:
        print("\nAnalysis interrupted by user.")
        sys.exit(0)
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()