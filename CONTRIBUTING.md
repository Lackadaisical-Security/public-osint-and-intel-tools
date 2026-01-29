# Contributing to Public OSINT & Intelligence Gathering Tools

## Welcome

We're building production-grade OSINT tools for security professionals. If you have skills and want to contribute quality code, you're in the right place.

## Quick Start

1. **Fork the repository**
2. **Clone your fork**: `git clone https://github.com/YOUR_USERNAME/public-osint-and-intel-tools.git`
3. **Create a branch**: `git checkout -b feature/your-feature-name`
4. **Make your changes**
5. **Test thoroughly**
6. **Submit a Pull Request**

## Before You Contribute

### Required Skills
- **Python**: Core language for most tools
- **OSINT Methodology**: Understanding of intelligence gathering techniques
- **Security Awareness**: Knowledge of OPSEC, privacy, and legal constraints
- **Git**: Basic version control proficiency

### Read These First
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) - Non-negotiable rules
- [SECURITY.md](SECURITY.md) - Security practices and vulnerability reporting
- [PRIVACY.md](PRIVACY.md) - Privacy and data handling guidelines
- [README.md](README.md) - Project overview and usage

## What We're Looking For

### High Priority Contributions
- **New OSINT Tools**: Well-tested intelligence gathering capabilities
- **Privacy/Anonymity Features**: Tor integration, proxy rotation, obfuscation
- **Performance Optimizations**: Faster execution, better resource usage
- **Bug Fixes**: Reproducible fixes with test cases
- **Documentation**: Clear, accurate technical documentation
- **Security Enhancements**: Vulnerability fixes, encryption improvements

### Not Interested In
- Trivial cosmetic changes (whitespace, formatting) without functional improvements
- "Refactoring" that doesn't improve performance or maintainability
- Adding dependencies without compelling justification
- Duplicating existing functionality
- Tools that violate legal/ethical guidelines

## Development Setup

### Environment Setup

```bash
# Clone repository
git clone https://github.com/Lackadaisical-Security/public-osint-and-intel-tools.git
cd public-osint-and-intel-tools

# Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install development dependencies
pip install black flake8 mypy pytest

# Create .env file from example
cp .env.example .env
# Add your API keys (never commit .env)
```

### Project Structure

```
public-osint-and-intel-tools/
├── tools/              # Core Python OSINT modules
├── advanced/           # Advanced intelligence gathering tools
├── privacy/            # Anonymity and OPSEC utilities
├── standalone/         # Self-contained scripts (various languages)
├── tools-multiplatform/# Multi-language implementations
│   ├── nodejs/        # Node.js tools
│   ├── c/             # C tools
│   ├── cpp/           # C++ tools
│   ├── dotnet/        # .NET tools
│   └── asm/           # Assembly tools
└── scripts/           # Installation and build scripts
```

## Code Standards

### Python Code

**Follow PEP 8**. Use these tools:
```bash
# Format code
black your_file.py

# Check style
flake8 your_file.py

# Type checking
mypy your_file.py
```

**Key Requirements:**
- Type hints for function signatures
- Docstrings for all public functions/classes
- Error handling with specific exceptions
- Logging instead of print statements
- No hardcoded credentials or API keys
- Production-ready code (no TODOs, no placeholders, no mock data)

**Example:**
```python
import logging
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class DomainIntel:
    """Domain intelligence gathering tool"""
    
    def gather_intel(self, domain: str) -> Dict[str, any]:
        """
        Gather comprehensive intelligence about a domain
        
        Args:
            domain: Target domain name
            
        Returns:
            Dictionary containing intelligence data
            
        Raises:
            ValueError: If domain is invalid
            ConnectionError: If network request fails
        """
        if not self._validate_domain(domain):
            raise ValueError(f"Invalid domain: {domain}")
        
        try:
            results = self._perform_lookup(domain)
            logger.info(f"Gathered intel for {domain}")
            return results
        except Exception as e:
            logger.error(f"Failed to gather intel: {e}")
            raise ConnectionError(f"Intelligence gathering failed: {e}")
```

### Other Languages

- **JavaScript/Node.js**: ESLint standard, JSDoc comments
- **C/C++**: Follow project conventions, memory safety critical
- **Go**: `gofmt` formatting, error handling required
- **Ruby**: RuboCop standards
- **PHP**: PSR-12 coding standard
- **Perl**: Perl::Critic recommendations
- **.NET**: Microsoft C# conventions

### Security Requirements

**Every contribution must:**
- Not introduce vulnerabilities (SQL injection, XSS, command injection, etc.)
- Validate all input data
- Use secure credential storage (never hardcode keys)
- Implement proper error handling (no stack trace leaks)
- Follow principle of least privilege
- Use HTTPS for external connections
- Implement rate limiting where appropriate

### Testing Requirements

**All new features require tests:**
```bash
# Run tests
pytest tests/

# Test specific module
pytest tests/test_domain_intel.py

# With coverage
pytest --cov=tools tests/
```

**Test Guidelines:**
- Unit tests for individual functions
- Integration tests for complete workflows
- Mock external API calls (don't hammer real services)
- Test edge cases and error conditions
- Aim for >80% code coverage

**Example Test:**
```python
import pytest
from tools.domain_intel import DomainIntel


def test_domain_intel_valid():
    intel = DomainIntel()
    result = intel.gather_intel("example.com")
    assert 'domain' in result
    assert result['domain'] == 'example.com'


def test_domain_intel_invalid():
    intel = DomainIntel()
    with pytest.raises(ValueError):
        intel.gather_intel("invalid domain!")
```

## Pull Request Process

### Before Submitting

1. **Test your changes thoroughly**
   ```bash
   # Run tests
   pytest tests/
   
   # Check code style
   black .
   flake8 .
   mypy tools/
   ```

2. **Update documentation**
   - Add/update docstrings
   - Update README.md if adding features
   - Add examples for new tools
   - Document any new dependencies

3. **Verify no secrets**
   ```bash
   # Remove any API keys, passwords, tokens
   grep -r "api_key\|password\|token" --exclude-dir=.git .
   ```

4. **Test with clean environment**
   ```bash
   # Fresh venv
   deactivate
   rm -rf venv
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   # Test your changes
   ```

### Pull Request Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Performance improvement
- [ ] Documentation update
- [ ] Security fix

## Testing
Describe how you tested this

## Checklist
- [ ] Code follows project style guidelines
- [ ] Tests pass (`pytest tests/`)
- [ ] Documentation updated
- [ ] No hardcoded credentials
- [ ] Commit messages are clear
- [ ] Changes are backwards compatible (or documented)

## Legal & Ethical
- [ ] Code is original or properly attributed
- [ ] No copyright violations
- [ ] Tools comply with legal requirements
- [ ] Proper authorization required for use
```

### Code Review Process

1. **Automated Checks**: CI/CD runs tests, linters, security scans
2. **Maintainer Review**: Technical review by project maintainers
3. **Feedback**: Address comments and requested changes
4. **Approval**: Requires maintainer approval
5. **Merge**: Squash and merge into main branch

**Review Criteria:**
- Code quality and style
- Test coverage
- Security implications
- Performance impact
- Documentation completeness
- Legal/ethical compliance

## Commit Message Guidelines

**Format:**
```
<type>(<scope>): <subject>

<body>

<footer>
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `perf`: Performance improvement
- `docs`: Documentation changes
- `style`: Code style changes (formatting)
- `refactor`: Code refactoring
- `test`: Test additions/changes
- `chore`: Maintenance tasks

**Examples:**
```
feat(tools): Add subdomain enumeration to domain intel

Implements advanced subdomain discovery using DNS brute-forcing
and certificate transparency logs. Includes rate limiting to
avoid detection.

Closes #123
```

```
fix(privacy): Correct Tor circuit renewal logic

Fixed bug where circuit renewal wasn't properly waiting for
new circuit establishment, causing connection failures.

Fixes #456
```

## Vulnerability Disclosure

**Found a security issue?** Don't open a public issue.

**Contact:** lackadaisicalresearch@pm.me (PGP preferred)

See [SECURITY.md](SECURITY.md) for full disclosure process.

## Legal Compliance

### Contribution License
By contributing, you agree that your contributions will be licensed under the MIT License.

### Original Work
- Only submit code you wrote or have rights to
- Properly attribute third-party code
- Don't submit copyrighted material
- Don't violate licenses

### Export Controls
Tools may be subject to export control laws. By contributing, you agree:
- Your contributions comply with export controls
- Tools won't be exported to sanctioned countries
- You understand dual-use technology implications

## Getting Help

### Questions?
- **GitHub Issues**: For bugs, feature requests
- **GitHub Discussions**: For general questions
- **Email**: lackadaisicalresearch@pm.me

### Resources
- [OSINT Framework](https://osintframework.com/)
- [SANS OSINT Resources](https://www.sans.org/blog/list-of-resource-links-from-open-source-intelligence-summit-2021/)
- [Python Documentation](https://docs.python.org/3/)
- [Git Documentation](https://git-scm.com/doc)

## Recognition

Quality contributors will be:
- Listed in CONTRIBUTORS.md
- Credited in release notes
- Acknowledged in project documentation

**Contribution is about technical merit, not ego.**

## Final Notes

- **Quality > Quantity**: One well-tested tool is better than ten broken ones
- **Documentation Matters**: Code without docs is incomplete
- **Security First**: Never compromise security for features
- **Legal Compliance**: Always respect laws and ethics
- **Be Professional**: Direct communication, technical arguments, professional conduct

**Welcome to the team. Build something excellent.**

---

**Copyright © 2025-2026 Lackadaisical Security. All rights reserved.**
