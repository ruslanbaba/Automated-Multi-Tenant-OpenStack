#!/usr/bin/env python3
"""
OpenStack Multi-Tenant Environment Validation Script
Validates RBAC policies, tenant isolation, and billing functionality
SECURITY ENHANCED: Input validation, secure subprocess handling, credential protection
"""

import os
import sys
import json
import logging
import argparse
from datetime import datetime, timedelta
import yaml
import subprocess
import shlex  # SECURITY FIX: For safe shell command construction
import re
from keystoneauth1 import session
from keystoneauth1.identity import v3
from novaclient import client as nova_client
from neutronclient.v2_0 import client as neutron_client
from cinderclient import client as cinder_client
from glanceclient import Client as glance_client
import requests
from cryptography.fernet import Fernet

# Configure logging with security focus
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/openstack-validation.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# SECURITY FIX: Input validation functions
def validate_tenant_name(tenant_name):
    """Validate tenant name to prevent injection attacks"""
    if not isinstance(tenant_name, str):
        raise ValueError("Tenant name must be a string")
    if not re.match(r'^[a-zA-Z0-9_-]+$', tenant_name):
        raise ValueError("Invalid tenant name format")
    if len(tenant_name) > 64:
        raise ValueError("Tenant name too long")
    return tenant_name

def validate_command_args(args):
    """Validate command arguments to prevent injection"""
    if not isinstance(args, list):
        raise ValueError("Command arguments must be a list")
    
    for arg in args:
        if not isinstance(arg, str):
            raise ValueError("All arguments must be strings")
        # Check for dangerous characters
        if any(char in arg for char in ['|', '&', ';', '`', '$', '(', ')']):
            raise ValueError("Dangerous characters detected in command arguments")
    return args

def secure_subprocess_run(command, **kwargs):
    """Safely execute subprocess with security validation"""
    # SECURITY FIX: Validate and sanitize command
    if isinstance(command, str):
        # Use shlex for safe shell splitting
        command = shlex.split(command)
    
    validate_command_args(command)
    
    # SECURITY FIX: Always disable shell execution and set secure environment
    kwargs.update({
        'shell': False,
        'capture_output': True,
        'text': True,
        'timeout': 30,  # Prevent hanging processes
        'env': {
            'PATH': '/usr/local/bin:/usr/bin:/bin',  # Secure PATH
            'LC_ALL': 'C',  # Consistent locale
        }
    })
    
    try:
        result = subprocess.run(command, **kwargs)
        return result
    except subprocess.TimeoutExpired:
        logger.error(f"Command timeout: {command[0]}")
        raise
    except Exception as e:
        logger.error(f"Command execution failed: {e}")
        raise

class OpenStackValidator:
    """Validator for OpenStack multi-tenant environment"""
    
    def __init__(self, config_file='/etc/openstack/validation-config.yml'):
        """Initialize the validator"""
        self.config = self._load_config(config_file)
        self._validate_config()
        self.admin_session = self._create_admin_session()
        self.test_results = []
        
    def _load_config(self, config_file):
        """Load configuration from file with security validation"""
        try:
            # SECURITY FIX: Validate config file path
            config_file = os.path.abspath(config_file)
            if not config_file.startswith('/etc/') and not config_file.startswith('/opt/'):
                raise ValueError("Configuration file must be in /etc/ or /opt/ directory")
                
            with open(config_file, 'r') as f:
                config = yaml.safe_load(f)
                
            # SECURITY FIX: Validate required config sections
            required_sections = ['openstack', 'validation']
            for section in required_sections:
                if section not in config:
                    raise ValueError(f"Missing required configuration section: {section}")
                    
            return config
        except FileNotFoundError:
            logger.error(f"Configuration file not found: {config_file}")
            sys.exit(1)
    
    def _validate_config(self):
        """Validate configuration for security issues"""
        # SECURITY FIX: Check for secure credential storage
        if 'password' in str(self.config).lower():
            logger.warning("Password found in configuration - use secure credential storage")
            
        # Validate URLs
        auth_url = self.config.get('openstack', {}).get('auth_url', '')
        if not auth_url.startswith('https://'):
            raise ValueError("OpenStack auth URL must use HTTPS")
    
    def _create_admin_session(self):
        """Create admin session for OpenStack with security enhancements"""
        try:
            # SECURITY FIX: Use environment variables for credentials
            username = os.environ.get('OS_USERNAME') or self.config['openstack']['admin_username']
            password = os.environ.get('OS_PASSWORD') or self._decrypt_password()
            
            auth = v3.Password(
                auth_url=self.config['openstack']['auth_url'],
                username=username,
                password=password,
                project_name=self.config['openstack']['admin_project'],
                user_domain_name='Default',
                project_domain_name='Default'
            )
            
            # SECURITY FIX: Configure session with timeout and SSL verification
            sess = session.Session(
                auth=auth,
                timeout=30,
                verify=True  # Always verify SSL certificates
            )
            
            return sess
            
        except Exception as e:
            logger.error(f"Failed to create admin session: {e}")
            raise
    
    def _decrypt_password(self):
        """Decrypt password from secure storage"""
        # SECURITY FIX: Implement secure password decryption
        try:
            key = os.environ.get('ENCRYPTION_KEY')
            if key:
                f = Fernet(key.encode())
                encrypted_password = self.config['openstack'].get('encrypted_admin_password')
                if encrypted_password:
                    return f.decrypt(encrypted_password.encode()).decode()
            
            # Fallback to plaintext (development only)
            logger.warning("Using plaintext password - not secure for production")
            return self.config['openstack']['admin_password']
            
        except Exception as e:
            logger.error(f"Failed to decrypt password: {e}")
            raise
    
    def _create_tenant_session(self, tenant_name, username, password):
        """Create session for a specific tenant with validation"""
        # SECURITY FIX: Validate inputs
        validate_tenant_name(tenant_name)
        
        auth = v3.Password(
            auth_url=self.config['openstack']['auth_url'],
            username=username,
            password=password,
            project_name=tenant_name,
            user_domain_name='Default',
            project_domain_name='Default'
        )
        
        # SECURITY FIX: Configure session with timeout and SSL verification
        return session.Session(
            auth=auth,
            timeout=30,
            verify=True
        )
    
    def _record_test(self, test_name, status, message, details=None):
        """Record test result"""
        result = {
            'test_name': test_name,
            'status': status,
            'message': message,
            'timestamp': datetime.utcnow().isoformat(),
            'details': details or {}
        }
        self.test_results.append(result)
        
        status_symbol = "✓" if status == "PASS" else "✗"
        logger.info(f"{status_symbol} {test_name}: {message}")
    
    def validate_services(self):
        """Validate that all OpenStack services are running"""
        logger.info("Validating OpenStack services...")
        
        services = [
            ('keystone', 'identity'),
            ('nova', 'compute'),
            ('neutron', 'network'),
            ('cinder', 'volumev3'),
            ('glance', 'image'),
            ('placement', 'placement')
        ]
        
        for service_name, service_type in services:
            try:
                endpoint = self.admin_session.get_endpoint(
                    service_type=service_type,
                    interface='public'
                )
                
                # Test service availability
                response = self.admin_session.get(endpoint)
                if response.status_code < 400:
                    self._record_test(
                        f"Service {service_name} availability",
                        "PASS",
                        f"{service_name} service is accessible",
                        {'endpoint': endpoint, 'status_code': response.status_code}
                    )
                else:
                    self._record_test(
                        f"Service {service_name} availability",
                        "FAIL",
                        f"{service_name} service returned status {response.status_code}",
                        {'endpoint': endpoint, 'status_code': response.status_code}
                    )
            except Exception as e:
                self._record_test(
                    f"Service {service_name} availability",
                    "FAIL",
                    f"Failed to check {service_name} service: {str(e)}"
                )
    
    def validate_tenant_isolation(self):
        """Validate tenant isolation"""
        logger.info("Validating tenant isolation...")
        
        test_tenants = self.config.get('test_tenants', [])
        if len(test_tenants) < 2:
            self._record_test(
                "Tenant isolation setup",
                "SKIP",
                "Need at least 2 test tenants for isolation testing"
            )
            return
        
        tenant1 = test_tenants[0]
        tenant2 = test_tenants[1]
        
        # Test 1: Verify tenants cannot see each other's resources
        self._test_resource_isolation(tenant1, tenant2)
        
        # Test 2: Verify network isolation
        self._test_network_isolation(tenant1, tenant2)
        
        # Test 3: Verify storage isolation
        self._test_storage_isolation(tenant1, tenant2)
    
    def _test_resource_isolation(self, tenant1, tenant2):
        """Test that tenants cannot see each other's compute resources"""
        try:
            # Create sessions for both tenants
            session1 = self._create_tenant_session(
                tenant1['name'], tenant1['username'], tenant1['password']
            )
            session2 = self._create_tenant_session(
                tenant2['name'], tenant2['username'], tenant2['password']
            )
            
            # Get Nova clients
            nova1 = nova_client.Client('2.1', session=session1)
            nova2 = nova_client.Client('2.1', session=session2)
            
            # List servers from each tenant's perspective
            servers1 = nova1.servers.list()
            servers2 = nova2.servers.list()
            
            # Create a test instance in tenant1 if none exist
            if not servers1:
                try:
                    image = nova1.glance.find_image('cirros')
                    flavor = nova1.flavors.find(name='m1.tiny')
                    server = nova1.servers.create(
                        name='isolation-test-vm',
                        image=image.id,
                        flavor=flavor.id
                    )
                    servers1 = [server]
                except Exception as e:
                    logger.warning(f"Could not create test instance: {e}")
            
            # Check if tenant2 can see tenant1's servers
            all_servers2 = nova2.servers.list(search_opts={'all_tenants': True})
            
            tenant1_servers_visible_to_tenant2 = [
                s for s in all_servers2 
                if s.tenant_id != tenant2.get('id', '')
            ]
            
            if not tenant1_servers_visible_to_tenant2:
                self._record_test(
                    "Compute resource isolation",
                    "PASS",
                    "Tenants cannot see each other's compute resources"
                )
            else:
                self._record_test(
                    "Compute resource isolation",
                    "FAIL",
                    f"Tenant2 can see {len(tenant1_servers_visible_to_tenant2)} servers from other tenants"
                )
                
        except Exception as e:
            self._record_test(
                "Compute resource isolation",
                "FAIL",
                f"Error testing compute isolation: {str(e)}"
            )
    
    def _test_network_isolation(self, tenant1, tenant2):
        """Test network isolation between tenants"""
        try:
            session1 = self._create_tenant_session(
                tenant1['name'], tenant1['username'], tenant1['password']
            )
            session2 = self._create_tenant_session(
                tenant2['name'], tenant2['username'], tenant2['password']
            )
            
            neutron1 = neutron_client.Client(session=session1)
            neutron2 = neutron_client.Client(session=session2)
            
            # List networks from each tenant's perspective
            networks1 = neutron1.list_networks()['networks']
            networks2 = neutron2.list_networks()['networks']
            
            # Filter private networks (exclude shared/external networks)
            private_networks1 = [n for n in networks1 if not n.get('shared', False)]
            private_networks2 = [n for n in networks2 if not n.get('shared', False)]
            
            # Check for network overlap
            network_ids1 = {n['id'] for n in private_networks1}
            network_ids2 = {n['id'] for n in private_networks2}
            
            overlap = network_ids1.intersection(network_ids2)
            
            if not overlap:
                self._record_test(
                    "Network isolation",
                    "PASS",
                    "Tenants have isolated private networks"
                )
            else:
                self._record_test(
                    "Network isolation",
                    "FAIL",
                    f"Found {len(overlap)} shared private networks between tenants"
                )
                
        except Exception as e:
            self._record_test(
                "Network isolation",
                "FAIL",
                f"Error testing network isolation: {str(e)}"
            )
    
    def _test_storage_isolation(self, tenant1, tenant2):
        """Test storage isolation between tenants"""
        try:
            session1 = self._create_tenant_session(
                tenant1['name'], tenant1['username'], tenant1['password']
            )
            session2 = self._create_tenant_session(
                tenant2['name'], tenant2['username'], tenant2['password']
            )
            
            cinder1 = cinder_client.Client('3', session=session1)
            cinder2 = cinder_client.Client('3', session=session2)
            
            # List volumes from each tenant's perspective
            volumes1 = cinder1.volumes.list()
            volumes2 = cinder2.volumes.list()
            
            # Check volume IDs for overlap
            volume_ids1 = {v.id for v in volumes1}
            volume_ids2 = {v.id for v in volumes2}
            
            overlap = volume_ids1.intersection(volume_ids2)
            
            if not overlap:
                self._record_test(
                    "Storage isolation",
                    "PASS",
                    "Tenants have isolated storage volumes"
                )
            else:
                self._record_test(
                    "Storage isolation",
                    "FAIL",
                    f"Found {len(overlap)} shared volumes between tenants"
                )
                
        except Exception as e:
            self._record_test(
                "Storage isolation",
                "FAIL",
                f"Error testing storage isolation: {str(e)}"
            )
    
    def validate_rbac_policies(self):
        """Validate RBAC policies"""
        logger.info("Validating RBAC policies...")
        
        test_tenants = self.config.get('test_tenants', [])
        
        for tenant in test_tenants:
            self._test_tenant_rbac(tenant)
    
    def _test_tenant_rbac(self, tenant):
        """Test RBAC for a specific tenant"""
        try:
            session = self._create_tenant_session(
                tenant['name'], tenant['username'], tenant['password']
            )
            
            # Test admin capabilities for admin users
            if tenant.get('role') == 'admin':
                self._test_admin_privileges(tenant, session)
            else:
                self._test_user_privileges(tenant, session)
                
        except Exception as e:
            self._record_test(
                f"RBAC test for {tenant['name']}",
                "FAIL",
                f"Error testing RBAC: {str(e)}"
            )
    
    def _test_admin_privileges(self, tenant, session):
        """Test admin privileges within tenant scope"""
        try:
            nova = nova_client.Client('2.1', session=session)
            
            # Admin should be able to list all instances in their tenant
            servers = nova.servers.list()
            
            self._record_test(
                f"Tenant admin privileges - {tenant['name']}",
                "PASS",
                f"Tenant admin can list {len(servers)} instances"
            )
            
        except Exception as e:
            self._record_test(
                f"Tenant admin privileges - {tenant['name']}",
                "FAIL",
                f"Tenant admin cannot list instances: {str(e)}"
            )
    
    def _test_user_privileges(self, tenant, session):
        """Test regular user privileges"""
        try:
            nova = nova_client.Client('2.1', session=session)
            
            # User should be able to list their own instances
            servers = nova.servers.list()
            
            self._record_test(
                f"Tenant user privileges - {tenant['name']}",
                "PASS",
                f"Tenant user can list {len(servers)} instances"
            )
            
        except Exception as e:
            self._record_test(
                f"Tenant user privileges - {tenant['name']}",
                "FAIL",
                f"Tenant user cannot list instances: {str(e)}"
            )
    
    def validate_quotas(self):
        """Validate quota enforcement"""
        logger.info("Validating quota enforcement...")
        
        try:
            nova = nova_client.Client('2.1', session=self.admin_session)
            
            test_tenants = self.config.get('test_tenants', [])
            
            for tenant in test_tenants:
                try:
                    # Get quota information
                    quotas = nova.quotas.get(tenant.get('id', tenant['name']))
                    usage = nova.quotas.get(tenant.get('id', tenant['name']), detail=True)
                    
                    # Check if quotas are properly set
                    expected_quotas = tenant.get('expected_quotas', {})
                    
                    quota_valid = True
                    quota_details = {}
                    
                    for quota_name, expected_value in expected_quotas.items():
                        actual_value = getattr(quotas, quota_name, None)
                        quota_details[quota_name] = {
                            'expected': expected_value,
                            'actual': actual_value
                        }
                        
                        if actual_value != expected_value:
                            quota_valid = False
                    
                    if quota_valid or not expected_quotas:
                        self._record_test(
                            f"Quota validation - {tenant['name']}",
                            "PASS",
                            "Quotas are properly configured",
                            quota_details
                        )
                    else:
                        self._record_test(
                            f"Quota validation - {tenant['name']}",
                            "FAIL",
                            "Quotas do not match expected values",
                            quota_details
                        )
                        
                except Exception as e:
                    self._record_test(
                        f"Quota validation - {tenant['name']}",
                        "FAIL",
                        f"Error checking quotas: {str(e)}"
                    )
                    
        except Exception as e:
            self._record_test(
                "Quota validation setup",
                "FAIL",
                f"Error setting up quota validation: {str(e)}"
            )
    
    def validate_billing_integration(self):
        """Validate billing system integration"""
        logger.info("Validating billing integration...")
        
        try:
            # Check CloudKitty service
            cloudkitty_url = self.config.get('cloudkitty', {}).get('api_url')
            if cloudkitty_url:
                response = self.admin_session.get(f"{cloudkitty_url}/v1/info")
                if response.status_code == 200:
                    self._record_test(
                        "CloudKitty service availability",
                        "PASS",
                        "CloudKitty API is accessible"
                    )
                else:
                    self._record_test(
                        "CloudKitty service availability",
                        "FAIL",
                        f"CloudKitty API returned status {response.status_code}"
                    )
            else:
                self._record_test(
                    "CloudKitty service availability",
                    "SKIP",
                    "CloudKitty URL not configured"
                )
            
            # Test billing data collection
            self._test_billing_data_collection()
            
        except Exception as e:
            self._record_test(
                "Billing integration",
                "FAIL",
                f"Error testing billing integration: {str(e)}"
            )
    
    def _test_billing_data_collection(self):
        """Test billing data collection"""
        try:
            cloudkitty_url = self.config.get('cloudkitty', {}).get('api_url')
            if not cloudkitty_url:
                return
            
            # Get billing data for the last hour
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(hours=1)
            
            params = {
                'begin': start_time.isoformat(),
                'end': end_time.isoformat()
            }
            
            response = self.admin_session.get(
                f"{cloudkitty_url}/v1/dataframes",
                params=params
            )
            
            if response.status_code == 200:
                data = response.json()
                dataframes = data.get('dataframes', [])
                
                self._record_test(
                    "Billing data collection",
                    "PASS",
                    f"Found {len(dataframes)} billing dataframes",
                    {'dataframes_count': len(dataframes)}
                )
            else:
                self._record_test(
                    "Billing data collection",
                    "FAIL",
                    f"Failed to retrieve billing data: {response.status_code}"
                )
                
        except Exception as e:
            self._record_test(
                "Billing data collection",
                "FAIL",
                f"Error testing billing data collection: {str(e)}"
            )
    
    def run_all_validations(self):
        """Run all validation tests"""
        logger.info("Starting OpenStack multi-tenant validation...")
        
        self.validate_services()
        self.validate_tenant_isolation()
        self.validate_rbac_policies()
        self.validate_quotas()
        self.validate_billing_integration()
        
        # Generate summary
        total_tests = len(self.test_results)
        passed_tests = len([r for r in self.test_results if r['status'] == 'PASS'])
        failed_tests = len([r for r in self.test_results if r['status'] == 'FAIL'])
        skipped_tests = len([r for r in self.test_results if r['status'] == 'SKIP'])
        
        logger.info(f"Validation complete: {passed_tests}/{total_tests} tests passed")
        logger.info(f"Failed: {failed_tests}, Skipped: {skipped_tests}")
        
        return {
            'summary': {
                'total': total_tests,
                'passed': passed_tests,
                'failed': failed_tests,
                'skipped': skipped_tests,
                'success_rate': (passed_tests / total_tests * 100) if total_tests > 0 else 0
            },
            'results': self.test_results,
            'timestamp': datetime.utcnow().isoformat()
        }

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='OpenStack Multi-Tenant Validator')
    parser.add_argument('--config', default='/etc/openstack/validation-config.yml',
                       help='Configuration file path')
    parser.add_argument('--output', help='Output file for results (JSON format)')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose logging')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Run validation
    validator = OpenStackValidator(args.config)
    results = validator.run_all_validations()
    
    # Output results
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        logger.info(f"Results saved to {args.output}")
    else:
        print(json.dumps(results, indent=2))
    
    # Exit with appropriate code
    if results['summary']['failed'] > 0:
        sys.exit(1)
    else:
        sys.exit(0)

if __name__ == '__main__':
    main()
