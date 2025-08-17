#!/usr/bin/env python3
"""
Security Compliance Monitoring Dashboard
Real-time monitoring and reporting for OpenStack security compliance
"""

import os
import sys
import json
import yaml
import time
import logging
import subprocess
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from enum import Enum

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/openstack-compliance-monitor.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class ComplianceStatus(Enum):
    """Compliance status enumeration"""
    COMPLIANT = "COMPLIANT"
    NON_COMPLIANT = "NON_COMPLIANT"
    WARNING = "WARNING"
    UNKNOWN = "UNKNOWN"

@dataclass
class ComplianceCheck:
    """Represents a compliance check result"""
    check_id: str
    name: str
    category: str
    status: ComplianceStatus
    score: float
    details: str
    remediation: str
    last_updated: datetime
    severity: str = "MEDIUM"

class SecurityComplianceMonitor:
    """Monitors and reports on security compliance"""
    
    def __init__(self, config_file: str = '/etc/openstack/security-config.yml'):
        """Initialize the compliance monitor"""
        self.config = self._load_config(config_file)
        self.checks = []
        self.monitoring_active = False
        self.alert_thresholds = self.config.get('compliance', {}).get('thresholds', {})
        self.monitoring_interval = self.config.get('compliance', {}).get('monitoring_interval', 300)
        
    def _load_config(self, config_file: str) -> Dict[str, Any]:
        """Load security configuration"""
        try:
            with open(config_file, 'r') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            logger.warning(f"Configuration file not found: {config_file}, using defaults")
            return self._get_default_config()
        except yaml.YAMLError as e:
            logger.error(f"Error parsing configuration: {e}")
            return self._get_default_config()
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration"""
        return {
            'compliance': {
                'standards': ['SOC2', 'ISO27001', 'NIST'],
                'thresholds': {
                    'critical_score': 90,
                    'warning_score': 80,
                    'max_critical_violations': 0,
                    'max_high_violations': 3
                },
                'monitoring_interval': 300,
                'alert_channels': ['email', 'webhook']
            }
        }
    
    def check_soc2_compliance(self) -> List[ComplianceCheck]:
        """Check SOC 2 compliance requirements"""
        checks = []
        
        # SOC 2 - CC1: Control Environment
        cc1_check = self._check_control_environment()
        checks.append(ComplianceCheck(
            check_id="SOC2-CC1",
            name="Control Environment",
            category="SOC2",
            status=cc1_check['status'],
            score=cc1_check['score'],
            details=cc1_check['details'],
            remediation=cc1_check['remediation'],
            last_updated=datetime.utcnow(),
            severity="HIGH"
        ))
        
        # SOC 2 - CC2: Communication and Information
        cc2_check = self._check_communication_controls()
        checks.append(ComplianceCheck(
            check_id="SOC2-CC2",
            name="Communication and Information",
            category="SOC2",
            status=cc2_check['status'],
            score=cc2_check['score'],
            details=cc2_check['details'],
            remediation=cc2_check['remediation'],
            last_updated=datetime.utcnow(),
            severity="MEDIUM"
        ))
        
        # SOC 2 - CC6: Logical and Physical Access Controls
        cc6_check = self._check_access_controls()
        checks.append(ComplianceCheck(
            check_id="SOC2-CC6",
            name="Logical and Physical Access Controls",
            category="SOC2",
            status=cc6_check['status'],
            score=cc6_check['score'],
            details=cc6_check['details'],
            remediation=cc6_check['remediation'],
            last_updated=datetime.utcnow(),
            severity="CRITICAL"
        ))
        
        # SOC 2 - CC7: System Operations
        cc7_check = self._check_system_operations()
        checks.append(ComplianceCheck(
            check_id="SOC2-CC7",
            name="System Operations",
            category="SOC2",
            status=cc7_check['status'],
            score=cc7_check['score'],
            details=cc7_check['details'],
            remediation=cc7_check['remediation'],
            last_updated=datetime.utcnow(),
            severity="HIGH"
        ))
        
        return checks
    
    def check_iso27001_compliance(self) -> List[ComplianceCheck]:
        """Check ISO 27001 compliance requirements"""
        checks = []
        
        # A.9: Access Control
        a9_check = self._check_iso_access_control()
        checks.append(ComplianceCheck(
            check_id="ISO27001-A9",
            name="Access Control",
            category="ISO27001",
            status=a9_check['status'],
            score=a9_check['score'],
            details=a9_check['details'],
            remediation=a9_check['remediation'],
            last_updated=datetime.utcnow(),
            severity="CRITICAL"
        ))
        
        # A.10: Cryptography
        a10_check = self._check_iso_cryptography()
        checks.append(ComplianceCheck(
            check_id="ISO27001-A10",
            name="Cryptography",
            category="ISO27001",
            status=a10_check['status'],
            score=a10_check['score'],
            details=a10_check['details'],
            remediation=a10_check['remediation'],
            last_updated=datetime.utcnow(),
            severity="HIGH"
        ))
        
        # A.12: Operations Security
        a12_check = self._check_iso_operations_security()
        checks.append(ComplianceCheck(
            check_id="ISO27001-A12",
            name="Operations Security",
            category="ISO27001",
            status=a12_check['status'],
            score=a12_check['score'],
            details=a12_check['details'],
            remediation=a12_check['remediation'],
            last_updated=datetime.utcnow(),
            severity="HIGH"
        ))
        
        # A.13: Communications Security
        a13_check = self._check_iso_communications_security()
        checks.append(ComplianceCheck(
            check_id="ISO27001-A13",
            name="Communications Security",
            category="ISO27001",
            status=a13_check['status'],
            score=a13_check['score'],
            details=a13_check['details'],
            remediation=a13_check['remediation'],
            last_updated=datetime.utcnow(),
            severity="HIGH"
        ))
        
        return checks
    
    def check_nist_compliance(self) -> List[ComplianceCheck]:
        """Check NIST Cybersecurity Framework compliance"""
        checks = []
        
        # NIST - Identify
        identify_check = self._check_nist_identify()
        checks.append(ComplianceCheck(
            check_id="NIST-ID",
            name="Identify",
            category="NIST",
            status=identify_check['status'],
            score=identify_check['score'],
            details=identify_check['details'],
            remediation=identify_check['remediation'],
            last_updated=datetime.utcnow(),
            severity="MEDIUM"
        ))
        
        # NIST - Protect
        protect_check = self._check_nist_protect()
        checks.append(ComplianceCheck(
            check_id="NIST-PR",
            name="Protect",
            category="NIST",
            status=protect_check['status'],
            score=protect_check['score'],
            details=protect_check['details'],
            remediation=protect_check['remediation'],
            last_updated=datetime.utcnow(),
            severity="CRITICAL"
        ))
        
        # NIST - Detect
        detect_check = self._check_nist_detect()
        checks.append(ComplianceCheck(
            check_id="NIST-DE",
            name="Detect",
            category="NIST",
            status=detect_check['status'],
            score=detect_check['score'],
            details=detect_check['details'],
            remediation=detect_check['remediation'],
            last_updated=datetime.utcnow(),
            severity="HIGH"
        ))
        
        # NIST - Respond
        respond_check = self._check_nist_respond()
        checks.append(ComplianceCheck(
            check_id="NIST-RS",
            name="Respond",
            category="NIST",
            status=respond_check['status'],
            score=respond_check['score'],
            details=respond_check['details'],
            remediation=respond_check['remediation'],
            last_updated=datetime.utcnow(),
            severity="HIGH"
        ))
        
        # NIST - Recover
        recover_check = self._check_nist_recover()
        checks.append(ComplianceCheck(
            check_id="NIST-RC",
            name="Recover",
            category="NIST",
            status=recover_check['status'],
            score=recover_check['score'],
            details=recover_check['details'],
            remediation=recover_check['remediation'],
            last_updated=datetime.utcnow(),
            severity="MEDIUM"
        ))
        
        return checks
    
    def _check_control_environment(self) -> Dict[str, Any]:
        """Check SOC 2 control environment"""
        score = 100.0
        issues = []
        
        # Check for security policies
        policy_files = [
            './docs/security-implementation.md',
            './config/security-config.yml',
            './ansible/playbooks/security-hardening.yml'
        ]
        
        existing_policies = sum(1 for f in policy_files if os.path.exists(f))
        if existing_policies < len(policy_files):
            score -= 20
            issues.append(f"Missing {len(policy_files) - existing_policies} security policy documents")
        
        # Check for automated security controls
        security_scripts = [
            './scripts/security/security-audit.py',
            './scripts/security/policy-enforcement.py'
        ]
        
        existing_scripts = sum(1 for f in security_scripts if os.path.exists(f))
        if existing_scripts < len(security_scripts):
            score -= 15
            issues.append(f"Missing {len(security_scripts) - existing_scripts} automated security controls")
        
        status = ComplianceStatus.COMPLIANT if score >= 90 else ComplianceStatus.NON_COMPLIANT
        
        return {
            'status': status,
            'score': score,
            'details': f"Control environment score: {score}/100. Issues: {', '.join(issues) if issues else 'None'}",
            'remediation': 'Implement missing security policies and automated controls'
        }
    
    def _check_communication_controls(self) -> Dict[str, Any]:
        """Check SOC 2 communication controls"""
        score = 100.0
        issues = []
        
        # Check for documentation
        docs = ['./README.md', './docs/']
        if not all(os.path.exists(d) for d in docs):
            score -= 25
            issues.append("Missing documentation")
        
        # Check for security notifications
        if not os.path.exists('./scripts/security/incident-response.py'):
            score -= 20
            issues.append("No incident response automation")
        
        status = ComplianceStatus.COMPLIANT if score >= 90 else ComplianceStatus.WARNING
        
        return {
            'status': status,
            'score': score,
            'details': f"Communication controls score: {score}/100. Issues: {', '.join(issues) if issues else 'None'}",
            'remediation': 'Implement missing documentation and notification systems'
        }
    
    def _check_access_controls(self) -> Dict[str, Any]:
        """Check SOC 2 access controls"""
        score = 100.0
        issues = []
        
        # Check SSH configuration
        sshd_config = '/etc/ssh/sshd_config'
        if os.path.exists(sshd_config):
            try:
                with open(sshd_config, 'r') as f:
                    content = f.read()
                
                if 'PermitRootLogin no' not in content:
                    score -= 30
                    issues.append("Root login not disabled")
                
                if 'PasswordAuthentication no' not in content:
                    score -= 25
                    issues.append("Password authentication not disabled")
                    
            except IOError:
                score -= 20
                issues.append("Cannot read SSH configuration")
        else:
            score -= 15
            issues.append("SSH configuration not found")
        
        # Check for MFA implementation
        if not any(os.path.exists(f) for f in ['./config/mfa.yml', '/etc/pam.d/sshd']):
            score -= 20
            issues.append("Multi-factor authentication not configured")
        
        status = ComplianceStatus.COMPLIANT if score >= 90 else ComplianceStatus.NON_COMPLIANT
        
        return {
            'status': status,
            'score': score,
            'details': f"Access controls score: {score}/100. Issues: {', '.join(issues) if issues else 'None'}",
            'remediation': 'Strengthen access controls, implement MFA, harden SSH'
        }
    
    def _check_system_operations(self) -> Dict[str, Any]:
        """Check SOC 2 system operations"""
        score = 100.0
        issues = []
        
        # Check for monitoring
        monitoring_configs = [
            './config/monitoring.yml',
            './scripts/monitoring/',
            '/etc/audit/auditd.conf'
        ]
        
        existing_monitoring = sum(1 for f in monitoring_configs if os.path.exists(f))
        if existing_monitoring < 2:
            score -= 30
            issues.append("Insufficient monitoring configuration")
        
        # Check for backup procedures
        if not any(os.path.exists(f) for f in ['./scripts/backup/', './ansible/playbooks/backup.yml']):
            score -= 25
            issues.append("No backup procedures documented")
        
        # Check for change management
        if not os.path.exists('./.github/workflows/'):
            score -= 20
            issues.append("No automated change management")
        
        status = ComplianceStatus.COMPLIANT if score >= 85 else ComplianceStatus.WARNING
        
        return {
            'status': status,
            'score': score,
            'details': f"System operations score: {score}/100. Issues: {', '.join(issues) if issues else 'None'}",
            'remediation': 'Implement comprehensive monitoring, backup, and change management'
        }
    
    def _check_iso_access_control(self) -> Dict[str, Any]:
        """Check ISO 27001 access control requirements"""
        score = 100.0
        issues = []
        
        # Check user account management
        ansible_user_mgmt = './ansible/playbooks/user-management.yml'
        if not os.path.exists(ansible_user_mgmt):
            score -= 30
            issues.append("No automated user management")
        
        # Check privilege escalation controls
        sudo_config = '/etc/sudoers'
        if os.path.exists(sudo_config):
            try:
                with open(sudo_config, 'r') as f:
                    content = f.read()
                
                if 'NOPASSWD' in content:
                    score -= 25
                    issues.append("Passwordless sudo configured")
                    
            except IOError:
                score -= 15
                issues.append("Cannot verify sudo configuration")
        
        status = ComplianceStatus.COMPLIANT if score >= 85 else ComplianceStatus.NON_COMPLIANT
        
        return {
            'status': status,
            'score': score,
            'details': f"ISO 27001 access control score: {score}/100. Issues: {', '.join(issues) if issues else 'None'}",
            'remediation': 'Implement proper user access controls and privilege management'
        }
    
    def _check_iso_cryptography(self) -> Dict[str, Any]:
        """Check ISO 27001 cryptography requirements"""
        score = 100.0
        issues = []
        
        # Check TLS configuration
        config_files = ['./config/environments/production.yml.example']
        for config_file in config_files:
            if os.path.exists(config_file):
                try:
                    with open(config_file, 'r') as f:
                        content = f.read()
                    
                    if 'tls_version: 1.3' not in content:
                        score -= 25
                        issues.append("TLS 1.3 not enforced")
                        
                except IOError:
                    continue
        
        # Check for key management
        if not os.path.exists('./ansible/group_vars/all/vault.yml'):
            score -= 30
            issues.append("No centralized key management")
        
        status = ComplianceStatus.COMPLIANT if score >= 90 else ComplianceStatus.WARNING
        
        return {
            'status': status,
            'score': score,
            'details': f"ISO 27001 cryptography score: {score}/100. Issues: {', '.join(issues) if issues else 'None'}",
            'remediation': 'Implement strong cryptography and key management'
        }
    
    def _check_iso_operations_security(self) -> Dict[str, Any]:
        """Check ISO 27001 operations security"""
        score = 100.0
        issues = []
        
        # Check for security procedures
        security_procedures = [
            './scripts/security/security-audit.py',
            './ansible/playbooks/security-hardening.yml'
        ]
        
        existing_procedures = sum(1 for f in security_procedures if os.path.exists(f))
        if existing_procedures < len(security_procedures):
            score -= 30
            issues.append("Missing security procedures")
        
        # Check for vulnerability management
        if not os.path.exists('./scripts/security/vulnerability-scan.py'):
            score -= 25
            issues.append("No automated vulnerability scanning")
        
        status = ComplianceStatus.COMPLIANT if score >= 85 else ComplianceStatus.WARNING
        
        return {
            'status': status,
            'score': score,
            'details': f"ISO 27001 operations security score: {score}/100. Issues: {', '.join(issues) if issues else 'None'}",
            'remediation': 'Implement comprehensive security operations procedures'
        }
    
    def _check_iso_communications_security(self) -> Dict[str, Any]:
        """Check ISO 27001 communications security"""
        score = 100.0
        issues = []
        
        # Check network security
        security_groups = './terraform/modules/security-groups/main.tf'
        if os.path.exists(security_groups):
            try:
                with open(security_groups, 'r') as f:
                    content = f.read()
                
                if '0.0.0.0/0' in content:
                    score -= 35
                    issues.append("Overly permissive network rules")
                    
            except IOError:
                score -= 20
                issues.append("Cannot verify network security configuration")
        
        # Check for network monitoring
        if not any(os.path.exists(f) for f in ['./scripts/monitoring/network-monitor.py', './config/network-monitoring.yml']):
            score -= 25
            issues.append("No network monitoring configured")
        
        status = ComplianceStatus.COMPLIANT if score >= 85 else ComplianceStatus.NON_COMPLIANT
        
        return {
            'status': status,
            'score': score,
            'details': f"ISO 27001 communications security score: {score}/100. Issues: {', '.join(issues) if issues else 'None'}",
            'remediation': 'Strengthen network security and implement monitoring'
        }
    
    def _check_nist_identify(self) -> Dict[str, Any]:
        """Check NIST Identify function"""
        score = 100.0
        issues = []
        
        # Check asset inventory
        if not os.path.exists('./inventory/'):
            score -= 30
            issues.append("No asset inventory")
        
        # Check risk assessment
        if not any(os.path.exists(f) for f in ['./docs/risk-assessment.md', './scripts/security/risk-assessment.py']):
            score -= 25
            issues.append("No risk assessment documented")
        
        status = ComplianceStatus.COMPLIANT if score >= 80 else ComplianceStatus.WARNING
        
        return {
            'status': status,
            'score': score,
            'details': f"NIST Identify score: {score}/100. Issues: {', '.join(issues) if issues else 'None'}",
            'remediation': 'Implement asset inventory and risk assessment processes'
        }
    
    def _check_nist_protect(self) -> Dict[str, Any]:
        """Check NIST Protect function"""
        score = 100.0
        issues = []
        
        # Check access controls
        if not os.path.exists('./ansible/playbooks/security-hardening.yml'):
            score -= 30
            issues.append("No security hardening playbook")
        
        # Check data protection
        if not any('encryption' in f for f in os.listdir('./config/') if os.path.isfile(os.path.join('./config/', f))):
            score -= 25
            issues.append("No encryption configuration found")
        
        status = ComplianceStatus.COMPLIANT if score >= 90 else ComplianceStatus.NON_COMPLIANT
        
        return {
            'status': status,
            'score': score,
            'details': f"NIST Protect score: {score}/100. Issues: {', '.join(issues) if issues else 'None'}",
            'remediation': 'Implement comprehensive protection controls'
        }
    
    def _check_nist_detect(self) -> Dict[str, Any]:
        """Check NIST Detect function"""
        score = 100.0
        issues = []
        
        # Check monitoring
        monitoring_scripts = [
            './scripts/monitoring/',
            './scripts/security/security-audit.py'
        ]
        
        existing_monitoring = sum(1 for f in monitoring_scripts if os.path.exists(f))
        if existing_monitoring < len(monitoring_scripts):
            score -= 35
            issues.append("Insufficient monitoring capabilities")
        
        # Check logging
        if not any(os.path.exists(f) for f in ['/etc/rsyslog.conf', './config/logging.yml']):
            score -= 25
            issues.append("No centralized logging configured")
        
        status = ComplianceStatus.COMPLIANT if score >= 85 else ComplianceStatus.WARNING
        
        return {
            'status': status,
            'score': score,
            'details': f"NIST Detect score: {score}/100. Issues: {', '.join(issues) if issues else 'None'}",
            'remediation': 'Implement comprehensive monitoring and logging'
        }
    
    def _check_nist_respond(self) -> Dict[str, Any]:
        """Check NIST Respond function"""
        score = 100.0
        issues = []
        
        # Check incident response
        if not os.path.exists('./scripts/security/incident-response.py'):
            score -= 40
            issues.append("No automated incident response")
        
        # Check communication plans
        if not any(os.path.exists(f) for f in ['./docs/incident-response-plan.md', './config/notifications.yml']):
            score -= 30
            issues.append("No incident communication plan")
        
        status = ComplianceStatus.COMPLIANT if score >= 80 else ComplianceStatus.NON_COMPLIANT
        
        return {
            'status': status,
            'score': score,
            'details': f"NIST Respond score: {score}/100. Issues: {', '.join(issues) if issues else 'None'}",
            'remediation': 'Implement incident response procedures and communication plans'
        }
    
    def _check_nist_recover(self) -> Dict[str, Any]:
        """Check NIST Recover function"""
        score = 100.0
        issues = []
        
        # Check backup procedures
        backup_items = [
            './scripts/backup/',
            './ansible/playbooks/backup.yml',
            './docs/disaster-recovery.md'
        ]
        
        existing_backups = sum(1 for f in backup_items if os.path.exists(f))
        if existing_backups < 2:
            score -= 40
            issues.append("Insufficient backup and recovery procedures")
        
        # Check restoration testing
        if not any(os.path.exists(f) for f in ['./tests/recovery/', './scripts/test-restore.py']):
            score -= 30
            issues.append("No recovery testing procedures")
        
        status = ComplianceStatus.COMPLIANT if score >= 75 else ComplianceStatus.WARNING
        
        return {
            'status': status,
            'score': score,
            'details': f"NIST Recover score: {score}/100. Issues: {', '.join(issues) if issues else 'None'}",
            'remediation': 'Implement comprehensive backup and recovery procedures'
        }
    
    def run_compliance_monitoring(self) -> Dict[str, Any]:
        """Run comprehensive compliance monitoring"""
        logger.info("Starting security compliance monitoring...")
        
        all_checks = []
        
        # Run compliance checks for each standard
        standards = self.config.get('compliance', {}).get('standards', ['SOC2', 'ISO27001', 'NIST'])
        
        if 'SOC2' in standards:
            all_checks.extend(self.check_soc2_compliance())
        
        if 'ISO27001' in standards:
            all_checks.extend(self.check_iso27001_compliance())
        
        if 'NIST' in standards:
            all_checks.extend(self.check_nist_compliance())
        
        # Calculate overall compliance scores
        compliance_summary = self._calculate_compliance_summary(all_checks)
        
        # Generate compliance report
        report = {
            'monitoring_timestamp': datetime.utcnow().isoformat(),
            'standards_monitored': standards,
            'total_checks': len(all_checks),
            'compliance_summary': compliance_summary,
            'checks': [asdict(check) for check in all_checks],
            'recommendations': self._generate_compliance_recommendations(all_checks),
            'alert_status': self._evaluate_alert_conditions(compliance_summary)
        }
        
        return report
    
    def _calculate_compliance_summary(self, checks: List[ComplianceCheck]) -> Dict[str, Any]:
        """Calculate compliance summary by standard"""
        summary = {}
        
        # Group checks by category (standard)
        by_category = {}
        for check in checks:
            if check.category not in by_category:
                by_category[check.category] = []
            by_category[check.category].append(check)
        
        # Calculate summary for each standard
        for category, category_checks in by_category.items():
            total_score = sum(check.score for check in category_checks)
            avg_score = total_score / len(category_checks) if category_checks else 0
            
            compliant_count = sum(1 for check in category_checks if check.status == ComplianceStatus.COMPLIANT)
            compliance_rate = (compliant_count / len(category_checks)) * 100 if category_checks else 0
            
            summary[category] = {
                'average_score': round(avg_score, 2),
                'compliance_rate': round(compliance_rate, 2),
                'total_checks': len(category_checks),
                'compliant_checks': compliant_count,
                'non_compliant_checks': len(category_checks) - compliant_count,
                'status': 'COMPLIANT' if avg_score >= 85 else 'NON_COMPLIANT'
            }
        
        # Calculate overall summary
        all_scores = [check.score for check in checks]
        overall_avg = sum(all_scores) / len(all_scores) if all_scores else 0
        
        overall_compliant = sum(1 for check in checks if check.status == ComplianceStatus.COMPLIANT)
        overall_rate = (overall_compliant / len(checks)) * 100 if checks else 0
        
        summary['overall'] = {
            'average_score': round(overall_avg, 2),
            'compliance_rate': round(overall_rate, 2),
            'total_checks': len(checks),
            'compliant_checks': overall_compliant,
            'non_compliant_checks': len(checks) - overall_compliant,
            'status': 'COMPLIANT' if overall_avg >= 85 else 'NON_COMPLIANT'
        }
        
        return summary
    
    def _generate_compliance_recommendations(self, checks: List[ComplianceCheck]) -> List[Dict[str, Any]]:
        """Generate prioritized compliance recommendations"""
        # Group non-compliant checks by severity
        non_compliant = [check for check in checks if check.status != ComplianceStatus.COMPLIANT]
        
        recommendations = []
        
        # Critical issues first
        critical_checks = [check for check in non_compliant if check.severity == 'CRITICAL']
        if critical_checks:
            recommendations.append({
                'priority': 'CRITICAL',
                'count': len(critical_checks),
                'description': 'Address critical compliance gaps immediately',
                'actions': list(set(check.remediation for check in critical_checks))
            })
        
        # High priority issues
        high_checks = [check for check in non_compliant if check.severity == 'HIGH']
        if high_checks:
            recommendations.append({
                'priority': 'HIGH',
                'count': len(high_checks),
                'description': 'Address high priority compliance issues',
                'actions': list(set(check.remediation for check in high_checks))
            })
        
        # Medium priority issues
        medium_checks = [check for check in non_compliant if check.severity == 'MEDIUM']
        if medium_checks:
            recommendations.append({
                'priority': 'MEDIUM',
                'count': len(medium_checks),
                'description': 'Address medium priority compliance issues',
                'actions': list(set(check.remediation for check in medium_checks))
            })
        
        return recommendations
    
    def _evaluate_alert_conditions(self, compliance_summary: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate if alert conditions are met"""
        alert_status = {
            'should_alert': False,
            'alert_level': 'INFO',
            'reasons': []
        }
        
        overall = compliance_summary.get('overall', {})
        
        # Check critical score threshold
        critical_threshold = self.alert_thresholds.get('critical_score', 90)
        if overall.get('average_score', 100) < critical_threshold:
            alert_status['should_alert'] = True
            alert_status['alert_level'] = 'CRITICAL'
            alert_status['reasons'].append(f"Overall compliance score {overall.get('average_score')} below critical threshold {critical_threshold}")
        
        # Check warning score threshold
        warning_threshold = self.alert_thresholds.get('warning_score', 80)
        if overall.get('average_score', 100) < warning_threshold:
            alert_status['should_alert'] = True
            if alert_status['alert_level'] != 'CRITICAL':
                alert_status['alert_level'] = 'WARNING'
            alert_status['reasons'].append(f"Overall compliance score {overall.get('average_score')} below warning threshold {warning_threshold}")
        
        # Check compliance rate
        if overall.get('compliance_rate', 100) < 85:
            alert_status['should_alert'] = True
            alert_status['reasons'].append(f"Compliance rate {overall.get('compliance_rate')}% below 85%")
        
        return alert_status
    
    def save_compliance_report(self, report: Dict[str, Any], output_file: str = 'compliance-report.json'):
        """Save compliance report to file"""
        try:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            logger.info(f"Compliance report saved to {output_file}")
        except IOError as e:
            logger.error(f"Failed to save compliance report: {e}")
    
    def start_continuous_monitoring(self):
        """Start continuous compliance monitoring"""
        self.monitoring_active = True
        
        def monitoring_loop():
            while self.monitoring_active:
                try:
                    report = self.run_compliance_monitoring()
                    timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
                    self.save_compliance_report(report, f'compliance-report-{timestamp}.json')
                    
                    # Check for alerts
                    alert_status = report.get('alert_status', {})
                    if alert_status.get('should_alert', False):
                        self._send_compliance_alert(alert_status, report)
                    
                    logger.info(f"Compliance monitoring cycle completed. Next check in {self.monitoring_interval} seconds.")
                    
                except Exception as e:
                    logger.error(f"Error in compliance monitoring cycle: {e}")
                
                time.sleep(self.monitoring_interval)
        
        monitoring_thread = threading.Thread(target=monitoring_loop, daemon=True)
        monitoring_thread.start()
        logger.info("Continuous compliance monitoring started")
    
    def stop_monitoring(self):
        """Stop continuous monitoring"""
        self.monitoring_active = False
        logger.info("Compliance monitoring stopped")
    
    def _send_compliance_alert(self, alert_status: Dict[str, Any], report: Dict[str, Any]):
        """Send compliance alerts"""
        alert_level = alert_status.get('alert_level', 'INFO')
        reasons = alert_status.get('reasons', [])
        
        logger.warning(f"COMPLIANCE ALERT [{alert_level}]: {'; '.join(reasons)}")
        
        # Additional alert handling could be implemented here
        # (email, webhook, etc.)

def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Security Compliance Monitoring Dashboard')
    parser.add_argument('--config', '-c', default='/etc/openstack/security-config.yml',
                       help='Security configuration file')
    parser.add_argument('--output', '-o', default='compliance-report.json',
                       help='Output report file')
    parser.add_argument('--continuous', action='store_true',
                       help='Run continuous monitoring')
    parser.add_argument('--interval', type=int, default=300,
                       help='Monitoring interval in seconds (for continuous mode)')
    parser.add_argument('--standards', nargs='+', choices=['SOC2', 'ISO27001', 'NIST'],
                       default=['SOC2', 'ISO27001', 'NIST'],
                       help='Compliance standards to monitor')
    
    args = parser.parse_args()
    
    try:
        # Create compliance monitor
        monitor = SecurityComplianceMonitor(args.config)
        
        # Override standards if specified
        if args.standards:
            monitor.config.setdefault('compliance', {})['standards'] = args.standards
        
        # Override interval if specified
        if args.interval:
            monitor.monitoring_interval = args.interval
        
        if args.continuous:
            # Start continuous monitoring
            monitor.start_continuous_monitoring()
            
            print(f"✅ Continuous compliance monitoring started")
            print(f"📊 Monitoring standards: {', '.join(args.standards)}")
            print(f"⏱️  Check interval: {args.interval} seconds")
            print("Press Ctrl+C to stop monitoring...")
            
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                monitor.stop_monitoring()
                print("\n🛑 Monitoring stopped")
        else:
            # Run single compliance check
            report = monitor.run_compliance_monitoring()
            
            # Save report
            monitor.save_compliance_report(report, args.output)
            
            # Print summary
            overall = report['compliance_summary']['overall']
            print(f"\n=== Security Compliance Summary ===")
            print(f"Overall Score: {overall['average_score']}/100")
            print(f"Compliance Rate: {overall['compliance_rate']}%")
            print(f"Compliant Checks: {overall['compliant_checks']}/{overall['total_checks']}")
            print(f"Standards: {', '.join(report['standards_monitored'])}")
            
            # Print by standard
            for standard in report['standards_monitored']:
                if standard in report['compliance_summary']:
                    std_summary = report['compliance_summary'][standard]
                    print(f"\n{standard}:")
                    print(f"  Score: {std_summary['average_score']}/100")
                    print(f"  Status: {std_summary['status']}")
                    print(f"  Compliant: {std_summary['compliant_checks']}/{std_summary['total_checks']}")
            
            # Print alert status
            alert_status = report.get('alert_status', {})
            if alert_status.get('should_alert', False):
                print(f"\n🚨 ALERT [{alert_status['alert_level']}]:")
                for reason in alert_status.get('reasons', []):
                    print(f"  - {reason}")
            
            print(f"\n📄 Full report saved to: {args.output}")
            
    except Exception as e:
        logger.error(f"Compliance monitoring failed: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
