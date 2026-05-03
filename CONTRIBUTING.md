# Contributing to AVIGHNA

Thank you for your interest in contributing to AVIGHNA! This document provides guidelines for contributing to the project.

## Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Help others learn and grow

## How to Contribute

### Reporting Bugs

1. Check if the bug has already been reported in Issues
2. If not, create a new issue with:
   - Clear title and description
   - Steps to reproduce
   - Expected vs actual behavior
   - System information (OS, Python version, etc.)
   - Screenshots if applicable

### Suggesting Features

1. Check if the feature has been suggested
2. Create a new issue with:
   - Clear description of the feature
   - Use case and benefits
   - Possible implementation approach

### Pull Requests

1. Fork the repository
2. Create a new branch: `git checkout -b feature/your-feature-name`
3. Make your changes
4. Test thoroughly
5. Commit with clear messages: `git commit -m "Add feature: description"`
6. Push to your fork: `git push origin feature/your-feature-name`
7. Open a Pull Request

### Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR-USERNAME/Avighna-defense-system.git
cd Avighna-defense-system

# Add upstream remote
git remote add upstream https://github.com/Bhakti-e/Avighna-defense-system.git

# Create virtual environment
python -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
cd frontend && npm install
```

### Code Style

**Python (Backend):**
- Follow PEP 8
- Use type hints where possible
- Add docstrings to functions
- Keep functions focused and small

**TypeScript/React (Frontend):**
- Use TypeScript for type safety
- Follow React best practices
- Use functional components with hooks
- Keep components small and reusable

### Testing

- Write tests for new features
- Ensure existing tests pass
- Test on multiple platforms if possible

### Commit Messages

- Use present tense: "Add feature" not "Added feature"
- Be descriptive but concise
- Reference issues: "Fix #123: Description"

## Areas for Contribution

### High Priority
- Router integration improvements
- Real threat intelligence feed integration
- ML model training pipeline
- Test coverage
- Documentation improvements

### Good First Issues
- UI/UX improvements
- Bug fixes
- Documentation updates
- Code refactoring

### Advanced
- New detection algorithms
- Performance optimizations
- Security enhancements
- Cloud deployment configurations

## Questions?

Feel free to open an issue for questions or reach out to the maintainers.

Thank you for contributing to AVIGHNA! 🛡️
