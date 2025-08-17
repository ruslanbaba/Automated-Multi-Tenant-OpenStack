# Contributing to OpenStack Multi-Tenant Environment

We welcome contributions to the OpenStack Multi-Tenant Environment project! This document provides guidelines for contributing to the project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Contributing Guidelines](#contributing-guidelines)
- [Pull Request Process](#pull-request-process)
- [Issue Reporting](#issue-reporting)
- [Documentation](#documentation)
- [Testing](#testing)
- [Security](#security)

## Code of Conduct

This project follows the [OpenStack Code of Conduct](https://www.openstack.org/legal/community-code-of-conduct/). By participating, you are expected to uphold this code.

### Our Standards

- **Be respectful** and inclusive of differing viewpoints and experiences
- **Be collaborative** and help others when possible
- **Be constructive** in discussions and feedback
- **Focus on what is best** for the community and project

## Getting Started

### Prerequisites

Before contributing, ensure you have:

- Git installed and configured
- Python 3.8+ installed
- Terraform 1.0+ installed
- Ansible 6.0+ installed
- Access to an OpenStack environment for testing (optional but recommended)

### Development Environment Setup

1. **Fork and Clone the Repository**
   ```bash
   git clone https://github.com/yourusername/Automated-Multi-Tenant-OpenStack.git
   cd Automated-Multi-Tenant-OpenStack
   ```

2. **Set Up Python Environment**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   pip install -r requirements-dev.txt
   ```

3. **Install Development Tools**
   ```bash
   # Install pre-commit hooks
   pre-commit install
   
   # Install testing tools
   pip install pytest pytest-cov ansible-lint yamllint
   ```

4. **Verify Setup**
   ```bash
   # Run linting
   make lint
   
   # Run tests
   make test
   ```

## Contributing Guidelines

### Types of Contributions

We welcome the following types of contributions:

- **Bug Fixes**: Fixing issues in existing code
- **New Features**: Adding new functionality
- **Documentation**: Improving or adding documentation
- **Testing**: Adding or improving tests
- **Performance**: Optimizing existing code
- **Security**: Improving security aspects

### Coding Standards

#### Python Code
- Follow [PEP 8](https://www.python.org/dev/peps/pep-0008/) style guidelines
- Use meaningful variable and function names
- Add docstrings to all functions and classes
- Include type hints where appropriate
- Maximum line length: 88 characters (Black formatter)

Example:
```python
def create_tenant(
    session: Session, 
    name: str, 
    description: str = None
) -> Dict[str, Any]:
    """
    Create a new OpenStack tenant.
    
    Args:
        session: Authenticated OpenStack session
        name: Tenant name
        description: Optional tenant description
        
    Returns:
        Dictionary containing tenant information
        
    Raises:
        TenantCreationError: If tenant creation fails
    """
    # Implementation here
```

#### Ansible Code
- Follow [Ansible best practices](https://docs.ansible.com/ansible/latest/user_guide/playbooks_best_practices.html)
- Use descriptive task names
- Include appropriate tags
- Use variables for reusable values
- Include error handling

Example:
```yaml
- name: Create OpenStack project
  openstack.cloud.project:
    cloud: "{{ cloud_name }}"
    state: present
    name: "{{ tenant_name }}"
    description: "{{ tenant_description | default('') }}"
    domain_id: default
    enabled: true
  register: project_result
  tags:
    - tenants
    - projects
  retries: 3
  delay: 5
```

#### Terraform Code
- Follow [Terraform best practices](https://www.terraform.io/docs/cloud/guides/recommended-practices/index.html)
- Use meaningful resource names
- Include descriptions for variables and outputs
- Use modules for reusable components
- Include appropriate tags

Example:
```hcl
resource "openstack_compute_instance_v2" "web_server" {
  name            = "${var.project_name}-web-${count.index + 1}"
  count           = var.instance_count
  image_id        = var.image_id
  flavor_id       = var.flavor_id
  key_pair        = var.key_pair_name
  security_groups = var.security_groups

  network {
    name = var.network_name
  }

  metadata = merge(var.common_tags, {
    Name = "${var.project_name}-web-${count.index + 1}"
    Type = "web_server"
  })

  tags = var.common_tags
}
```

### Git Workflow

1. **Create a Feature Branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make Changes**
   - Write clean, well-documented code
   - Include appropriate tests
   - Update documentation if needed

3. **Commit Changes**
   ```bash
   git add .
   git commit -m "feat: add tenant isolation validation"
   ```

4. **Push to Your Fork**
   ```bash
   git push origin feature/your-feature-name
   ```

### Commit Message Format

We follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

```
<type>[optional scope]: <description>

[optional body]

[optional footer(s)]
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

**Examples:**
```
feat(ansible): add tenant onboarding playbook
fix(terraform): correct security group rule configuration
docs(readme): update installation instructions
test(billing): add unit tests for cost calculation
```

## Pull Request Process

### Before Submitting

1. **Update Documentation**
   - Update README.md if needed
   - Add or update relevant documentation
   - Include inline code comments

2. **Add Tests**
   - Unit tests for new functions
   - Integration tests for new features
   - Ensure all tests pass

3. **Run Quality Checks**
   ```bash
   make lint
   make test
   make security-check
   ```

### Pull Request Template

When creating a PR, include:

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Documentation update
- [ ] Performance improvement
- [ ] Other (please describe)

## Testing
- [ ] Unit tests added/updated
- [ ] Integration tests added/updated
- [ ] Manual testing completed

## Checklist
- [ ] Code follows project style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] Tests pass locally
- [ ] No new security vulnerabilities introduced
```

### Review Process

1. **Automated Checks**: All PRs must pass automated checks
2. **Code Review**: At least one maintainer must review and approve
3. **Testing**: Changes must be tested in a staging environment
4. **Documentation**: Documentation must be updated if applicable

## Issue Reporting

### Bug Reports

When reporting bugs, include:

- **Environment details**: OS, Python version, OpenStack version
- **Steps to reproduce**: Clear, numbered steps
- **Expected behavior**: What should happen
- **Actual behavior**: What actually happens
- **Logs**: Relevant error messages or logs
- **Additional context**: Screenshots, configuration files, etc.

### Feature Requests

When requesting features, include:

- **Use case**: Why is this feature needed?
- **Proposed solution**: How should it work?
- **Alternatives considered**: Other approaches considered
- **Additional context**: Examples, mockups, etc.

## Documentation

### Types of Documentation

- **API Documentation**: Automatically generated from docstrings
- **User Guides**: Step-by-step instructions
- **Deployment Guides**: Installation and configuration
- **Architecture Docs**: System design and components
- **Troubleshooting**: Common issues and solutions

### Documentation Standards

- Use clear, concise language
- Include examples and code snippets
- Keep documentation up-to-date with code changes
- Use proper Markdown formatting
- Include diagrams for complex concepts

## Testing

### Test Categories

1. **Unit Tests**: Test individual functions and classes
2. **Integration Tests**: Test component interactions
3. **End-to-End Tests**: Test complete workflows
4. **Performance Tests**: Test system performance
5. **Security Tests**: Test for security vulnerabilities

### Running Tests

```bash
# Run all tests
make test

# Run specific test categories
make test-unit
make test-integration
make test-security

# Run tests with coverage
make test-coverage
```

### Writing Tests

- Use descriptive test names
- Test both success and failure cases
- Mock external dependencies
- Include edge cases
- Maintain test isolation

Example:
```python
def test_create_tenant_success():
    """Test successful tenant creation."""
    # Setup
    mock_session = Mock()
    tenant_name = "test-tenant"
    
    # Execute
    result = create_tenant(mock_session, tenant_name)
    
    # Assert
    assert result['name'] == tenant_name
    assert result['enabled'] is True
    mock_session.post.assert_called_once()

def test_create_tenant_duplicate_name():
    """Test tenant creation with duplicate name."""
    # Setup
    mock_session = Mock()
    mock_session.post.side_effect = ConflictError("Tenant exists")
    
    # Execute & Assert
    with pytest.raises(TenantCreationError):
        create_tenant(mock_session, "existing-tenant")
```

## Security

### Security Guidelines

- **Never commit secrets**: Use environment variables or secret management
- **Validate inputs**: Sanitize all user inputs
- **Use secure defaults**: Follow security best practices
- **Regular updates**: Keep dependencies updated
- **Access control**: Implement proper authorization

### Reporting Security Issues

For security-related issues:

1. **Do not** create a public issue
2. **Email** security concerns to: security@example.com
3. **Include** detailed information about the vulnerability
4. **Allow** reasonable time for response before disclosure

### Security Testing

```bash
# Run security scans
make security-check

# Check for vulnerable dependencies
safety check

# Run secrets scanner
detect-secrets scan --all-files
```

## Release Process

### Versioning

We follow [Semantic Versioning](https://semver.org/):

- **MAJOR**: Breaking changes
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes (backward compatible)

### Release Checklist

1. Update version numbers
2. Update CHANGELOG.md
3. Create release branch
4. Run full test suite
5. Update documentation
6. Create GitHub release
7. Deploy to staging
8. Deploy to production

## Community

### Communication Channels

- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: General questions and discussions
- **Slack**: Real-time chat (invite-only)
- **Mailing List**: Announcements and important updates

### Meetings

- **Weekly Standup**: Tuesdays at 10 AM UTC
- **Monthly Planning**: First Friday of each month
- **Quarterly Review**: End of each quarter

## Recognition

Contributors are recognized through:

- **Contributors file**: Listed in CONTRIBUTORS.md
- **Release notes**: Mentioned in release announcements
- **Blog posts**: Featured contributor spotlights
- **Conference talks**: Speaking opportunities

## Getting Help

If you need help:

1. **Check documentation**: Start with the docs
2. **Search issues**: Look for similar problems
3. **Ask questions**: Use GitHub Discussions
4. **Join community**: Connect with other contributors

Thank you for contributing to the OpenStack Multi-Tenant Environment project!
