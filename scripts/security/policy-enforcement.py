#!/usr/bin/env python3
"""
Security Policy Enforcement Engine
Enforces security policies across OpenStack multi-tenant environment
"""

import os
import sys
import json
import logging
import yaml
import re
import hashlib
from datetime import datetime, timedelta
from pathlib import Path
import subprocess
import shlex
from typing import Dict, List, Optional, Any

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/openstack-policy-enforcement.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class PolicyViolation:
    """Represents a security policy violation"""
    
    def __init__(self, rule_id: str, severity: str, description: str, 
                 resource: str, remediation: str):
        self.rule_id = rule_id
        self.severity = severity
        self.description = description
        self.resource = resource
        self.remediation = remediation
        self.timestamp = datetime.utcnow()

class SecurityPolicyEngine:
    """Enforces security policies and detects violations"""
    
    def __init__(self, config_file: str = '/etc/openstack/security-config.yml'):
        """Initialize the policy engine"""
        self.config = self._load_config(config_file)
        self.violations = []
        self.policies = self._load_policies()
        
    def _load_config(self, config_file: str) -> Dict[str, Any]:
        """Load security configuration"""
        try:
            with open(config_file, 'r') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            logger.error(f"Configuration file not found: {config_file}")
            sys.exit(1)
        except yaml.YAMLError as e:
            logger.error(f"Error parsing configuration: {e}")
            sys.exit(1)
    
    def _load_policies(self) -> Dict[str, Any]:
        """Load security policies from configuration"""
        return self.config.get('validation_rules', {})
    
    def enforce_credential_policies(self) -> List[PolicyViolation]:
        """Enforce credential security policies"""
        violations = []
        cred_policies = self.policies.get('credentials', {})
        
        if not cred_policies.get('no_hardcoded_passwords', False):
            return violations
            
        # Scan for hardcoded passwords
        config_paths = [
            '/etc/openstack',
            '/etc/keystone',
            '/etc/nova',
            '/etc/neutron',
            '/etc/cinder',
            '/etc/glance',
            './config',
            './ansible',
            './terraform'
        ]
        
        dangerous_patterns = [
            r'password\s*=\s*["\']?[^"\'{\s]+["\']?',
            r'secret\s*=\s*["\']?[^"\'{\s]+["\']?',
            r'token\s*=\s*["\']?[^"\'{\s]+["\']?',
            r'admin.*=.*["\']?[^"\'{\s]+["\']?'
        ]
        
        for config_path in config_paths:
            if not os.path.exists(config_path):
                continue
                
            for root, dirs, files in os.walk(config_path):
                for file in files:
                    if file.endswith(('.conf', '.yml', '.yaml', '.cfg', '.ini', '.tf', '.tfvars')):
                        file_path = os.path.join(root, file)
                        try:
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read()
                                
                            for pattern in dangerous_patterns:
                                matches = re.finditer(pattern, content, re.IGNORECASE)
                                for match in matches:
                                    # Skip if it's a template variable or environment variable
                                    if any(template in match.group() for template in ['{{', '${', 'vault_']):
                                        continue
                                    
                                    violations.append(PolicyViolation(
                                        rule_id="CRED-001",
                                        severity="CRITICAL",
                                        description=f"Hardcoded credential found in {file_path}",
                                        resource=file_path,
                                        remediation="Move credential to Ansible Vault or environment variable"
                                    ))
                                    
                        except (IOError, UnicodeDecodeError):
                            continue
        
        return violations
    
    def enforce_network_policies(self) -> List[PolicyViolation]:
        """Enforce network security policies"""
        violations = []
        network_policies = self.policies.get('network', {})
        
        # Check for overly permissive security group rules
        if network_policies.get('api_network_isolation', False):
            terraform_files = []
            for root, dirs, files in os.walk('./terraform'):
                for file in files:
                    if file.endswith('.tf'):
                        terraform_files.append(os.path.join(root, file))
            
            for tf_file in terraform_files:
                try:
                    with open(tf_file, 'r') as f:
                        content = f.read()
                    
                    # Check for 0.0.0.0/0 in security groups
                    if 'remote_ip_prefix.*=.*"0.0.0.0/0"' in content or 'source_cidr_block.*=.*"0.0.0.0/0"' in content:
                        violations.append(PolicyViolation(
                            rule_id="NET-001",
                            severity="HIGH",
                            description=f"Overly permissive security group rule in {tf_file}",
                            resource=tf_file,
                            remediation="Restrict access to specific networks only"
                        ))
                        
                except IOError:
                    continue
        
        return violations
    
    def enforce_tls_policies(self) -> List[PolicyViolation]:
        """Enforce TLS/SSL security policies"""
        violations = []
        tls_policies = self.policies.get('tls', {})
        
        min_version = tls_policies.get('min_version', '1.3')
        
        # Check OpenStack service configurations
        service_configs = [
            '/etc/keystone/keystone.conf',
            '/etc/nova/nova.conf',
            '/etc/neutron/neutron.conf',
            '/etc/cinder/cinder.conf',
            '/etc/glance/glance-api.conf'
        ]
        
        for config_file in service_configs:
            if not os.path.exists(config_file):
                continue
                
            try:
                with open(config_file, 'r') as f:
                    content = f.read()
                
                # Check for SSL/TLS configuration
                if 'ssl_enable' not in content and 'use_ssl' not in content:
                    violations.append(PolicyViolation(
                        rule_id="TLS-001",
                        severity="HIGH",
                        description=f"SSL/TLS not configured in {config_file}",
                        resource=config_file,
                        remediation="Enable SSL/TLS for the service"
                    ))
                
                # Check for weak TLS versions
                weak_versions = ['1.0', '1.1', '1.2'] if min_version == '1.3' else ['1.0', '1.1']
                for version in weak_versions:
                    if f'tls_version.*{version}' in content.lower():
                        violations.append(PolicyViolation(
                            rule_id="TLS-002",
                            severity="MEDIUM",
                            description=f"Weak TLS version {version} configured in {config_file}",
                            resource=config_file,
                            remediation=f"Upgrade to TLS {min_version} or higher"
                        ))
                        
            except IOError:
                continue
        
        return violations
    
    def enforce_file_permission_policies(self) -> List[PolicyViolation]:
        """Enforce file permission security policies"""
        violations = []
        file_policies = self.policies.get('file_permissions', {})
        
        sensitive_files = file_policies.get('sensitive_files', [])
        
        for file_config in sensitive_files:
            file_path = file_config.get('path', '')
            max_permissions = file_config.get('max_permissions', '0600')
            expected_owner = file_config.get('owner', 'root')
            
            # Handle wildcard paths
            if '*' in file_path:
                import glob
                files = glob.glob(file_path)
            else:
                files = [file_path] if os.path.exists(file_path) else []
            
            for actual_file in files:
                try:
                    stat_info = os.stat(actual_file)
                    actual_permissions = oct(stat_info.st_mode)[-3:]
                    
                    # Check permissions
                    if int(actual_permissions, 8) > int(max_permissions, 8):
                        violations.append(PolicyViolation(
                            rule_id="FILE-001",
                            severity="HIGH",
                            description=f"File {actual_file} has overly permissive permissions {actual_permissions}",
                            resource=actual_file,
                            remediation=f"Change permissions to {max_permissions} or more restrictive"
                        ))
                    
                    # Check for world-writable files
                    if file_policies.get('no_world_writable', False) and int(actual_permissions[2]) & 2:
                        violations.append(PolicyViolation(
                            rule_id="FILE-002",
                            severity="CRITICAL",
                            description=f"File {actual_file} is world-writable",
                            resource=actual_file,
                            remediation="Remove world-write permissions"
                        ))
                        
                except (OSError, ValueError):
                    continue
        
        return violations
    
    def enforce_authentication_policies(self) -> List[PolicyViolation]:
        """Enforce authentication security policies"""
        violations = []
        auth_policies = self.policies.get('authentication', {})
        
        # Check SSH configuration
        sshd_config = '/etc/ssh/sshd_config'
        if os.path.exists(sshd_config):
            try:
                with open(sshd_config, 'r') as f:
                    content = f.read()
                
                # Check for disabled root login
                if auth_policies.get('disable_root_login', False):
                    if 'PermitRootLogin no' not in content:
                        violations.append(PolicyViolation(
                            rule_id="AUTH-001",
                            severity="HIGH",
                            description="Root login not disabled in SSH configuration",
                            resource=sshd_config,
                            remediation="Set PermitRootLogin no in sshd_config"
                        ))
                
                # Check for disabled password authentication
                if auth_policies.get('disable_password_auth', False):
                    if 'PasswordAuthentication no' not in content:
                        violations.append(PolicyViolation(
                            rule_id="AUTH-002",
                            severity="HIGH",
                            description="Password authentication not disabled in SSH",
                            resource=sshd_config,
                            remediation="Set PasswordAuthentication no in sshd_config"
                        ))
                
                # Check max auth tries
                max_tries = auth_policies.get('max_auth_tries', 3)
                if f'MaxAuthTries {max_tries}' not in content:
                    violations.append(PolicyViolation(
                        rule_id="AUTH-003",
                        severity="MEDIUM",
                        description=f"MaxAuthTries not set to {max_tries} or less",
                        resource=sshd_config,
                        remediation=f"Set MaxAuthTries {max_tries} in sshd_config"
                    ))
                    
            except IOError:
                pass
        
        return violations
    
    def enforce_api_policies(self) -> List[PolicyViolation]:
        """Enforce API security policies"""
        violations = []
        api_policies = self.policies.get('api', {})
        
        # Check rate limiting configuration
        if api_policies.get('rate_limiting', False):
            # Check various configuration files for rate limiting
            config_files = [
                '/etc/apache2/sites-enabled/keystone.conf',
                '/etc/nginx/sites-enabled/openstack-api',
                './config/environments/production.yml.example'
            ]
            
            for config_file in config_files:
                if not os.path.exists(config_file):
                    continue
                    
                try:
                    with open(config_file, 'r') as f:
                        content = f.read()
                    
                    # Look for rate limiting configuration
                    rate_limit_indicators = [
                        'rate_limit',
                        'max_requests',
                        'throttle',
                        'limit_req'
                    ]
                    
                    has_rate_limiting = any(indicator in content.lower() for indicator in rate_limit_indicators)
                    if not has_rate_limiting:
                        violations.append(PolicyViolation(
                            rule_id="API-001",
                            severity="MEDIUM",
                            description=f"Rate limiting not configured in {config_file}",
                            resource=config_file,
                            remediation="Configure API rate limiting"
                        ))
                        
                except IOError:
                    continue
        
        return violations
    
    def enforce_audit_policies(self) -> List[PolicyViolation]:
        """Enforce audit and logging policies"""
        violations = []
        audit_policies = self.policies.get('audit', {})
        
        min_retention = audit_policies.get('retention_days_min', 365)
        
        # Check audit configuration files
        audit_configs = [
            '/etc/audit/auditd.conf',
            '/etc/rsyslog.conf',
            './config/environments/production.yml.example'
        ]
        
        for config_file in audit_configs:
            if not os.path.exists(config_file):
                continue
                
            try:
                with open(config_file, 'r') as f:
                    content = f.read()
                
                # Check retention configuration
                retention_patterns = [
                    r'retention.*(\d+)',
                    r'log_retention.*(\d+)',
                    r'rotate.*(\d+)'
                ]
                
                for pattern in retention_patterns:
                    matches = re.finditer(pattern, content, re.IGNORECASE)
                    for match in matches:
                        retention_value = int(match.group(1))
                        if retention_value < min_retention:
                            violations.append(PolicyViolation(
                                rule_id="AUDIT-001",
                                severity="MEDIUM",
                                description=f"Audit retention {retention_value} days below minimum {min_retention}",
                                resource=config_file,
                                remediation=f"Increase retention to at least {min_retention} days"
                            ))
                            
            except (IOError, ValueError):
                continue
        
        return violations
    
    def run_policy_enforcement(self) -> Dict[str, Any]:
        """Run comprehensive policy enforcement"""
        logger.info("Starting security policy enforcement...")
        
        # Run all policy enforcement checks
        enforcement_functions = [
            self.enforce_credential_policies,
            self.enforce_network_policies,
            self.enforce_tls_policies,
            self.enforce_file_permission_policies,
            self.enforce_authentication_policies,
            self.enforce_api_policies,
            self.enforce_audit_policies
        ]
        
        all_violations = []
        for func in enforcement_functions:
            try:
                violations = func()
                all_violations.extend(violations)
                logger.info(f"{func.__name__}: Found {len(violations)} violations")
            except Exception as e:
                logger.error(f"Error in {func.__name__}: {e}")
        
        # Categorize violations by severity
        violations_by_severity = {
            'CRITICAL': [v for v in all_violations if v.severity == 'CRITICAL'],
            'HIGH': [v for v in all_violations if v.severity == 'HIGH'],
            'MEDIUM': [v for v in all_violations if v.severity == 'MEDIUM'],
            'LOW': [v for v in all_violations if v.severity == 'LOW']
        }
        
        # Calculate compliance score
        compliance_score = self._calculate_compliance_score(all_violations)
        
        # Generate enforcement report
        report = {
            'enforcement_timestamp': datetime.utcnow().isoformat(),
            'total_violations': len(all_violations),
            'violations_by_severity': {
                severity: len(violations) 
                for severity, violations in violations_by_severity.items()
            },
            'compliance_score': compliance_score,
            'violations': [
                {
                    'rule_id': v.rule_id,
                    'severity': v.severity,
                    'description': v.description,
                    'resource': v.resource,
                    'remediation': v.remediation,
                    'timestamp': v.timestamp.isoformat()
                }
                for v in all_violations
            ],
            'recommendations': self._generate_remediation_plan(all_violations)
        }
        
        return report
    
    def _calculate_compliance_score(self, violations: List[PolicyViolation]) -> float:
        """Calculate overall compliance score"""
        if not violations:
            return 100.0
        
        # Weight violations by severity
        severity_weights = {'CRITICAL': 25, 'HIGH': 10, 'MEDIUM': 5, 'LOW': 1}
        total_penalty = sum(
            severity_weights.get(v.severity, 1) for v in violations
        )
        
        # Calculate score (max penalty of 100)
        score = max(0.0, 100.0 - min(100.0, total_penalty))
        return round(score, 2)
    
    def _generate_remediation_plan(self, violations: List[PolicyViolation]) -> List[Dict[str, Any]]:
        """Generate prioritized remediation plan"""
        # Group violations by resource and priority
        priority_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
        
        remediation_plan = []
        for severity in priority_order:
            severity_violations = [v for v in violations if v.severity == severity]
            if severity_violations:
                remediation_plan.append({
                    'priority': severity,
                    'count': len(severity_violations),
                    'estimated_effort': self._estimate_effort(severity_violations),
                    'actions': list(set(v.remediation for v in severity_violations))
                })
        
        return remediation_plan
    
    def _estimate_effort(self, violations: List[PolicyViolation]) -> str:
        """Estimate effort required to fix violations"""
        count = len(violations)
        if count <= 5:
            return "LOW"
        elif count <= 15:
            return "MEDIUM"
        else:
            return "HIGH"
    
    def save_report(self, report: Dict[str, Any], output_file: str = 'policy-enforcement-report.json'):
        """Save enforcement report to file"""
        try:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            logger.info(f"Policy enforcement report saved to {output_file}")
        except IOError as e:
            logger.error(f"Failed to save report: {e}")

def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Security Policy Enforcement Engine')
    parser.add_argument('--config', '-c', default='/etc/openstack/security-config.yml',
                       help='Security configuration file')
    parser.add_argument('--output', '-o', default='policy-enforcement-report.json',
                       help='Output report file')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Verbose output')
    parser.add_argument('--fail-on-critical', action='store_true',
                       help='Exit with error code if critical violations found')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        # Create policy engine
        engine = SecurityPolicyEngine(args.config)
        
        # Run enforcement
        report = engine.run_policy_enforcement()
        
        # Save report
        engine.save_report(report, args.output)
        
        # Print summary
        print(f"\n=== Security Policy Enforcement Summary ===")
        print(f"Compliance Score: {report['compliance_score']}/100")
        print(f"Total Violations: {report['total_violations']}")
        print(f"Critical: {report['violations_by_severity']['CRITICAL']}")
        print(f"High: {report['violations_by_severity']['HIGH']}")
        print(f"Medium: {report['violations_by_severity']['MEDIUM']}")
        print(f"Low: {report['violations_by_severity']['LOW']}")
        print(f"\nFull report saved to: {args.output}")
        
        # Exit with error if critical violations and flag is set
        if args.fail_on_critical and report['violations_by_severity']['CRITICAL'] > 0:
            print("\n❌ Critical policy violations found - deployment blocked")
            sys.exit(1)
        elif report['compliance_score'] < 90:
            print("\n⚠️  Compliance score below 90 - review required")
            sys.exit(2)
        else:
            print("\n✅ Policy enforcement completed successfully")
            
    except Exception as e:
        logger.error(f"Policy enforcement failed: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
