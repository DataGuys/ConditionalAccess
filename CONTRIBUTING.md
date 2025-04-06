# Contributing to Conditional Access Analyzer

Thank you for your interest in contributing to the Conditional Access Analyzer! This document provides guidelines and instructions for contributing to this project.

## Code of Conduct

Please be respectful and constructive in all interactions related to this project.

## How to Contribute

### Reporting Issues

If you find a bug or have a suggestion for improvement:

1. Check if the issue already exists in the [Issues](https://github.com/DataGuys/ConditionalAccess/issues) section
2. If not, create a new issue with:
   - A clear, descriptive title
   - A detailed description of the issue/suggestion
   - Steps to reproduce (for bugs)
   - Expected vs. actual behavior
   - Screenshots if applicable
   - Your environment details (PowerShell version, OS, etc.)

### Pull Requests

1. Fork the repository
2. Create a new branch for your changes
3. Make your changes
4. Test your changes thoroughly
5. Submit a pull request with:
   - A clear description of the changes
   - Reference to any related issues
   - Documentation updates if applicable

## Development Guidelines

### Code Style

- Follow PowerShell best practices and naming conventions
- Use meaningful variable, parameter, and function names
- Include comment-based help for all functions
- Use [PSScriptAnalyzer](https://github.com/PowerShell/PSScriptAnalyzer) to check your code

### Function Guidelines

- Functions should have a clear, single responsibility
- Include proper error handling
- Support the `-Verbose` parameter where appropriate
- Maintain backward compatibility when possible

### Testing

- Test all changes in both PowerShell 5.1 and PowerShell Core
- Test in Azure Cloud Shell
- Verify connectivity works with different authentication methods

## Documentation

- Update README.md with any new features or changes
- Keep examples up to date
- Update help comments in the code

## Release Process

1. Changes will be reviewed for inclusion in the next release
2. Version numbers follow [Semantic Versioning](https://semver.org/)
3. New releases are published to GitHub and optionally to the PowerShell Gallery

## Resources

- [PowerShell Best Practices and Style Guide](https://github.com/PoshCode/PowerShellPracticeAndStyle)
- [Microsoft Graph API Documentation](https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccesspolicy?view=graph-rest-1.0)
- [Microsoft Entra ID Documentation](https://learn.microsoft.com/en-us/entra/identity/)

## Questions?

If you have questions about contributing, please open an issue with your question or contact the repository maintainers.

Thank you for your contributions!
