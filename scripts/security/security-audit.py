#!/usr/bin/env python3
"""
OpenStack Multi-Tenant Security Audit Script
Comprehensive security validation and vulnerability assessment
"""

import os
import sys
import json
import logging
import argparse
import subprocess
import shlex
import re
import hashlib
import ssl
import socket
from datetime import datetime, timedelta
import yaml
import requests
from urllib.parse import urlparse
import secrets
import string
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# Configure secure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/openstack-security-audit.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class SecurityAuditor:
    """Comprehensive security auditor for OpenStack multi-tenant environment"""
    
    def __init__(self, config_file='/etc/openstack/security-config.yml'):
        """Initialize the security auditor"""
        self.config = self._load_config(config_file)
        self.audit_results = []
        self.vulnerabilities = []
        self.recommendations = []
        
    def _load_config(self, config_file):
        """Load configuration with security validation"""
        try:
            config_file = os.path.abspath(config_file)
            if not config_file.startswith(('/etc/', '/opt/')):
                raise ValueError("Configuration file must be in /etc/ or /opt/")
                
            with open(config_file, 'r') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            logger.warning(f"Config file not found: {config_file}, using defaults")
            return self._get_default_config()
    
    def _get_default_config(self):
        """Get default security configuration"""
        return {
            'openstack': {
                'auth_url': 'https://localhost:5000/v3',
                'services': ['keystone', 'nova', 'neutron', 'cinder', 'glance']
            },
            'security': {
                'tls_min_version': '1.3',
                'cipher_suites': ['TLS_AES_256_GCM_SHA384', 'TLS_CHACHA20_POLY1305_SHA256'],
                'password_policy': {
                    'min_length': 14,
                    'require_complexity': True
                }
            }
        }
    
    def audit_credentials_exposure(self):
        """Audit for exposed credentials in configuration files"""
        logger.info("Auditing for credential exposure...")
        
        dangerous_patterns = [
            r'password\s*=\s*["\']?[^"\'\s]+["\']?',
            r'secret\s*=\s*["\']?[^"\'\s]+["\']?',
            r'token\s*=\s*["\']?[^"\'\s]+["\']?',
            r'key\s*=\s*["\']?[^"\'\s]+["\']?',
            r'admin.*=.*["\']?[^"\'\s]+["\']?'
        ]
        
        config_paths = [
            '/etc/openstack',
            '/etc/keystone',
            '/etc/nova',
            '/etc/neutron',
            '/etc/cinder',
            '/etc/glance',
            './config',
            './ansible'
        ]
        
        vulnerabilities_found = []
        
        for config_path in config_paths:
            if not os.path.exists(config_path):
                continue
                
            for root, dirs, files in os.walk(config_path):
                for file in files:
                    if file.endswith(('.conf', '.yml', '.yaml', '.cfg', '.ini')):
                        file_path = os.path.join(root, file)
                        try:
                            with open(file_path, 'r') as f:
                                content = f.read()
                                
                            for pattern in dangerous_patterns:
                                matches = re.finditer(pattern, content, re.IGNORECASE)
                                for match in matches:
                                    # Check if it's a template variable (acceptable)
                                    if '{{' in match.group() or '${' in match.group():
                                        continue
                                    
                                    vulnerabilities_found.append({
                                        'file': file_path,
                                        'line': content[:match.start()].count('\n') + 1,
                                        'pattern': pattern,
                                        'severity': 'CRITICAL'
                                    })
                                    
                        except (IOError, UnicodeDecodeError):
                            continue
        
        if vulnerabilities_found:
            self.vulnerabilities.extend(vulnerabilities_found)
            logger.error(f"Found {len(vulnerabilities_found)} credential exposure vulnerabilities")
        else:
            logger.info("No credential exposure vulnerabilities found")
            
        return vulnerabilities_found
    
    def audit_tls_configuration(self):
        """Audit TLS/SSL configuration for security issues"""
        logger.info("Auditing TLS/SSL configuration...")
        
        tls_issues = []
        endpoints = [
            ('keystone', 5000),
            ('nova', 8774),
            ('neutron', 9696),
            ('cinder', 8776),
            ('glance', 9292)
        ]
        
        for service, port in endpoints:
            try:
                # Check if service is using HTTPS
                context = ssl.create_default_context()
                context.minimum_version = ssl.TLSVersion.TLSv1_3
                
                sock = socket.create_connection(('localhost', port), timeout=10)
                ssock = context.wrap_socket(sock, server_hostname='localhost')
                
                # Get certificate info
                cert = ssock.getpeercert(binary_form=True)
                x509_cert = x509.load_der_x509_certificate(cert, default_backend())
                
                # Check certificate validity
                now = datetime.utcnow()
                if x509_cert.not_valid_after < now:
                    tls_issues.append({
                        'service': service,
                        'issue': 'Certificate expired',
                        'severity': 'HIGH'
                    })
                
                if x509_cert.not_valid_after < (now + timedelta(days=30)):
                    tls_issues.append({
                        'service': service,
                        'issue': 'Certificate expires within 30 days',
                        'severity': 'MEDIUM'
                    })
                
                # Check TLS version
                if ssock.version < 'TLSv1.3':
                    tls_issues.append({
                        'service': service,
                        'issue': f'Using {ssock.version}, should use TLS 1.3',
                        'severity': 'HIGH'
                    })
                
                ssock.close()
                
            except (socket.error, ssl.SSLError, ConnectionRefusedError):
                tls_issues.append({
                    'service': service,
                    'issue': 'Service not using HTTPS or not accessible',
                    'severity': 'CRITICAL'
                })
        
        if tls_issues:
            self.vulnerabilities.extend(tls_issues)
            logger.error(f"Found {len(tls_issues)} TLS configuration issues")
        else:
            logger.info("TLS configuration appears secure")
            
        return tls_issues
    
    def audit_file_permissions(self):
        """Audit file permissions for security issues"""
        logger.info("Auditing file permissions...")
        
        permission_issues = []
        sensitive_files = [
            '/etc/keystone/keystone.conf',
            '/etc/nova/nova.conf',
            '/etc/neutron/neutron.conf',
            '/etc/cinder/cinder.conf',
            '/etc/glance/glance-api.conf',
            '/etc/ssl/private/*',
            '~/.ssh/openstack_key.pem'
        ]
        
        for file_pattern in sensitive_files:
            if '*' in file_pattern:
                import glob
                files = glob.glob(file_pattern)
            else:
                files = [file_pattern] if os.path.exists(file_pattern) else []
            
            for file_path in files:
                try:
                    stat_info = os.stat(file_path)
                    permissions = oct(stat_info.st_mode)[-3:]
                    
                    # Check for overly permissive permissions
                    if int(permissions[1]) > 0 or int(permissions[2]) > 0:
                        permission_issues.append({
                            'file': file_path,
                            'permissions': permissions,
                            'issue': 'File accessible by group/others',
                            'severity': 'HIGH'
                        })
                    
                    # Check for world-writable files
                    if int(permissions[2]) & 2:
                        permission_issues.append({
                            'file': file_path,
                            'permissions': permissions,
                            'issue': 'File is world-writable',
                            'severity': 'CRITICAL'
                        })
                        
                except (OSError, ValueError):
                    continue
        
        if permission_issues:
            self.vulnerabilities.extend(permission_issues)
            logger.error(f"Found {len(permission_issues)} file permission issues")
        else:
            logger.info("File permissions appear secure")
            
        return permission_issues
    
    def audit_password_policies(self):
        """Audit password policies and weak passwords"""
        logger.info("Auditing password policies...")
        
        policy_issues = []
        
        # Check Keystone password policy configuration
        keystone_config = '/etc/keystone/keystone.conf'
        if os.path.exists(keystone_config):
            try:
                with open(keystone_config, 'r') as f:
                    content = f.read()
                
                # Check for password policy settings
                required_settings = [
                    ('password_regex', r'password_regex\s*='),
                    ('password_regex_description', r'password_regex_description\s*='),
                    ('lockout_failure_attempts', r'lockout_failure_attempts\s*='),
                    ('lockout_duration', r'lockout_duration\s*=')
                ]
                
                for setting, pattern in required_settings:
                    if not re.search(pattern, content):
                        policy_issues.append({
                            'setting': setting,
                            'issue': f'Password policy setting {setting} not configured',
                            'severity': 'MEDIUM'
                        })
                        
            except IOError:
                policy_issues.append({
                    'setting': 'keystone_config',
                    'issue': 'Cannot read Keystone configuration',
                    'severity': 'HIGH'
                })
        
        if policy_issues:
            self.vulnerabilities.extend(policy_issues)
            logger.warning(f"Found {len(policy_issues)} password policy issues")
        else:
            logger.info("Password policies appear configured")
            
        return policy_issues
    
    def audit_network_security(self):
        """Audit network security configuration"""
        logger.info("Auditing network security...")
        
        network_issues = []
        
        # Check for open ports
        dangerous_ports = [
            (22, 'SSH'),
            (3306, 'MySQL'),
            (5432, 'PostgreSQL'),
            (6379, 'Redis'),
            (11211, 'Memcached')
        ]
        
        for port, service in dangerous_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex(('0.0.0.0', port))
                sock.close()
                
                if result == 0:
                    network_issues.append({
                        'port': port,
                        'service': service,
                        'issue': f'{service} port {port} is open and accessible',
                        'severity': 'HIGH' if port in [3306, 5432, 6379] else 'MEDIUM'
                    })
                    
            except socket.error:
                continue
        
        # Check firewall status
        try:
            result = subprocess.run(['ufw', 'status'], capture_output=True, text=True)
            if 'Status: inactive' in result.stdout:
                network_issues.append({
                    'service': 'firewall',
                    'issue': 'UFW firewall is not active',
                    'severity': 'HIGH'
                })
        except FileNotFoundError:
            pass  # UFW not installed
        
        if network_issues:
            self.vulnerabilities.extend(network_issues)
            logger.warning(f"Found {len(network_issues)} network security issues")
        else:
            logger.info("Network security appears configured")
            
        return network_issues
    
    def generate_security_recommendations(self):
        """Generate security hardening recommendations"""
        logger.info("Generating security recommendations...")
        
        recommendations = [
            {
                'category': 'Authentication',
                'title': 'Implement Multi-Factor Authentication',
                'description': 'Enable MFA for all administrative accounts',
                'priority': 'HIGH'
            },
            {
                'category': 'Encryption',
                'title': 'Enable Encryption at Rest',
                'description': 'Encrypt all data stores including databases and volumes',
                'priority': 'HIGH'
            },
            {
                'category': 'Network Security',
                'title': 'Implement Network Segmentation',
                'description': 'Use VLANs and security groups for network isolation',
                'priority': 'MEDIUM'
            },
            {
                'category': 'Monitoring',
                'title': 'Enhanced Security Monitoring',
                'description': 'Implement real-time security event monitoring and SIEM',
                'priority': 'HIGH'
            },
            {
                'category': 'Access Control',
                'title': 'Regular Access Reviews',
                'description': 'Conduct monthly reviews of user access and permissions',
                'priority': 'MEDIUM'
            },
            {
                'category': 'Vulnerability Management',
                'title': 'Automated Security Scanning',
                'description': 'Implement automated vulnerability scanning and patch management',
                'priority': 'HIGH'
            }
        ]
        
        self.recommendations.extend(recommendations)
        return recommendations
    
    def run_comprehensive_audit(self):
        """Run comprehensive security audit"""
        logger.info("Starting comprehensive security audit...")
        
        audit_functions = [
            self.audit_credentials_exposure,
            self.audit_tls_configuration,
            self.audit_file_permissions,
            self.audit_password_policies,
            self.audit_network_security
        ]
        
        for audit_func in audit_functions:
            try:
                audit_func()
            except Exception as e:
                logger.error(f"Error in {audit_func.__name__}: {e}")
        
        # Generate recommendations
        self.generate_security_recommendations()
        
        # Compile final report
        report = {
            'audit_timestamp': datetime.utcnow().isoformat(),
            'total_vulnerabilities': len(self.vulnerabilities),
            'vulnerabilities_by_severity': {
                'CRITICAL': len([v for v in self.vulnerabilities if v.get('severity') == 'CRITICAL']),
                'HIGH': len([v for v in self.vulnerabilities if v.get('severity') == 'HIGH']),
                'MEDIUM': len([v for v in self.vulnerabilities if v.get('severity') == 'MEDIUM']),
                'LOW': len([v for v in self.vulnerabilities if v.get('severity') == 'LOW'])
            },
            'vulnerabilities': self.vulnerabilities,
            'recommendations': self.recommendations,
            'overall_security_score': self._calculate_security_score()
        }
        
        return report
    
    def _calculate_security_score(self):
        """Calculate overall security score (0-100)"""
        if not self.vulnerabilities:
            return 100
        
        # Weight vulnerabilities by severity
        severity_weights = {'CRITICAL': 25, 'HIGH': 10, 'MEDIUM': 5, 'LOW': 1}
        total_penalty = sum(severity_weights.get(v.get('severity', 'LOW'), 1) 
                          for v in self.vulnerabilities)
        
        # Calculate score (max penalty of 100)
        score = max(0, 100 - min(100, total_penalty))
        return score
    
    def save_report(self, report, output_file='security-audit-report.json'):
        """Save audit report to file"""
        try:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            logger.info(f"Security audit report saved to {output_file}")
        except IOError as e:
            logger.error(f"Failed to save report: {e}")

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='OpenStack Security Audit Tool')
    parser.add_argument('--config', '-c', default='/etc/openstack/security-config.yml',
                       help='Security configuration file')
    parser.add_argument('--output', '-o', default='security-audit-report.json',
                       help='Output report file')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Verbose output')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        auditor = SecurityAuditor(args.config)
        report = auditor.run_comprehensive_audit()
        auditor.save_report(report, args.output)
        
        # Print summary
        print(f"\n=== Security Audit Summary ===")
        print(f"Overall Security Score: {report['overall_security_score']}/100")
        print(f"Total Vulnerabilities: {report['total_vulnerabilities']}")
        print(f"Critical: {report['vulnerabilities_by_severity']['CRITICAL']}")
        print(f"High: {report['vulnerabilities_by_severity']['HIGH']}")
        print(f"Medium: {report['vulnerabilities_by_severity']['MEDIUM']}")
        print(f"Low: {report['vulnerabilities_by_severity']['LOW']}")
        print(f"\nFull report saved to: {args.output}")
        
        # Exit with error code if critical vulnerabilities found
        if report['vulnerabilities_by_severity']['CRITICAL'] > 0:
            sys.exit(1)
            
    except Exception as e:
        logger.error(f"Security audit failed: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
