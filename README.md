# PassEntropy

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.6%2B-blue.svg)
![Version](https://img.shields.io/badge/version-1.0.0-green.svg)

A comprehensive CLI tool for analyzing password strength using advanced entropy calculations and pattern recognition algorithms. PassEntropy goes beyond simple character counting to provide deep security insights into password quality.

## Features

### 🔬 **Scientific Analysis**
- **Entropy Calculation**: Measures password randomness in bits using information theory
- **Character Space Analysis**: Calculates theoretical keyspace size
- **Mathematical Scoring**: 100-point scoring system based on cryptographic principles

### 🔍 **Advanced Pattern Detection**
- Sequential character patterns (abc, 123, qwerty)
- Keyboard layout patterns (qwer, asdf, zxcv)
- Repeated character sequences
- Common character substitutions (@, 3, 1, 0, $, 7)
- Date and year patterns
- Common password dictionary matching

### 📊 **Comprehensive Reporting**
- Detailed strength assessment with actionable recommendations
- Character composition breakdown
- Security vulnerability identification
- Attack resistance estimates

### 🛡️ **Security-First Design**
- Secure password input (hidden typing)
- No password storage or logging
- Privacy-focused output options
- Professional security recommendations

## Installation

### Prerequisites
- Python 3.6 or higher
- Standard library only (no external dependencies)

### Quick Install
```bash
# Clone or download the script
wget https://raw.githubusercontent.com/user/passentropy/main/passentropy.py
chmod +x passentropy.py

# Or make it globally available
sudo cp passentropy.py /usr/local/bin/passentropy
sudo chmod +x /usr/local/bin/passentropy
```

## Usage

### Interactive Mode (Recommended)
```bash
python passentropy.py
# or if installed globally:
passentropy
```
Prompts for secure password input with hidden typing.

### Command Line Analysis
```bash
# Analyze a single password
python passentropy.py -p "MyPassword123!"

# Quiet mode (strength and score only)
python passentropy.py -q -p "MyPassword123!"
```

### Batch Analysis
```bash
# Analyze passwords from file
python passentropy.py -f passwords.txt

# Combine with quiet mode for bulk processing
python passentropy.py -q -f passwords.txt
```

### Advanced Options
```bash
# Show password in output (security risk)
python passentropy.py --no-hide -p "MyPassword123!"

# Get help
python passentropy.py -h
```

## Understanding the Analysis

### Strength Categories
- **Very Strong** (80-100): Excellent security, resistant to all common attacks
- **Strong** (60-79): Good security, suitable for most purposes
- **Moderate** (40-59): Adequate for low-risk accounts, consider strengthening
- **Weak** (20-39): Vulnerable to attacks, should be changed
- **Very Weak** (0-19): Easily cracked, immediate change required

### Entropy Guidelines
- **>60 bits**: Resistant to offline attacks
- **40-60 bits**: Adequate for online attacks with rate limiting
- **<40 bits**: Vulnerable to modern cracking techniques

### Scoring Breakdown
The 100-point scoring system evaluates:

| Component | Points | Criteria |
|-----------|---------|----------|
| **Length** | 0-25 | 12+ chars = full points |
| **Entropy** | 0-30 | 60+ bits = full points |
| **Diversity** | 0-25 | All character types = full points |
| **Patterns** | -20 | Penalty for predictable sequences |
| **Common** | -30 | Penalty for dictionary passwords |


## Security Best Practices

### Password Creation Guidelines
1. **Length**: Use at least 12 characters, preferably 16+
2. **Complexity**: Mix uppercase, lowercase, digits, and symbols
3. **Unpredictability**: Avoid personal information and common patterns
4. **Uniqueness**: Use different passwords for different accounts

### Using PassEntropy Safely
- Always use interactive mode for sensitive passwords
- Never include passwords in command history
- Use the `-q` flag for batch processing to minimize exposure
- Regularly analyze and update your passwords

## File Input Format

For batch analysis, create a text file with one password per line:

```text
password123
MySecureP@ssw0rd!
qwerty123
Tr0ub4dor&3
```

```bash
python passentropy.py -f my_passwords.txt
```

## Technical Details

### Entropy Calculation
PassEntropy calculates Shannon entropy using the formula:
```
Entropy = Length × log₂(Character_Space)
```

Where Character_Space is determined by the types of characters used:
- Lowercase letters: 26 characters
- Uppercase letters: 26 characters  
- Digits: 10 characters
- Special symbols: 32+ characters

### Pattern Recognition Algorithm
The tool uses multiple detection methods:
- **String matching** for sequential patterns
- **Regular expressions** for repeated characters
- **Dictionary lookups** for common passwords
- **Heuristic analysis** for keyboard patterns

## Contributing

Contributions are welcome! Areas for improvement:
- Additional pattern recognition algorithms
- Localization for non-English patterns
- Integration with breach databases
- Machine learning-based pattern detection

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

PassEntropy is a security analysis tool. While it provides comprehensive password strength assessment, no tool can guarantee absolute security. Always follow current security best practices and consider using a reputable password manager.

## Support

For issues, feature requests, or questions:
- Open an issue on GitHub
- Check existing documentation
- Follow security best practices

---

