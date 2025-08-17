# Deployment Guide for OpenStack Multi-Tenant Environment

## Overview

This guide provides step-by-step instructions for deploying an enterprise-grade OpenStack multi-tenant environment with RBAC and billing integration.

## Prerequisites

### Hardware Requirements

#### Controller Node
- **vCPUs**: 8+ cores
- **RAM**: 32 GB minimum, 64 GB recommended
- **Storage**: 100 GB SSD for OS, 500 GB for services
- **Network**: 4 NICs (Management, API, Storage, External)

#### Compute Nodes (2x)
- **vCPUs**: 16+ cores
- **RAM**: 64 GB minimum, 128 GB recommended
- **Storage**: 100 GB SSD for OS, 1 TB for local storage
- **Network**: 3 NICs (Management, Storage, Tenant)

#### Monitoring Node
- **vCPUs**: 4 cores
- **RAM**: 16 GB
- **Storage**: 200 GB SSD
- **Network**: 2 NICs (Management, API)

#### Billing Node
- **vCPUs**: 2 cores
- **RAM**: 8 GB
- **Storage**: 100 GB SSD
- **Network**: 2 NICs (Management, API)

### Software Requirements

- **Operating System**: Ubuntu 22.04 LTS
- **OpenStack Release**: Zed or newer
- **Terraform**: >= 1.0
- **Ansible**: >= 6.0
- **Python**: >= 3.8
- **Docker**: >= 20.10 (for some components)

### Network Requirements

- **Management Network**: 10.0.0.0/24
- **API Network**: 10.0.1.0/24
- **Storage Network**: 10.0.2.0/24
- **Tenant Network**: 10.0.3.0/24
- **External Network**: Provider-specific

## Pre-Deployment Setup

### 1. Environment Preparation

```bash
# Clone the repository
git clone https://github.com/ruslanbaba/Automated-Multi-Tenant-OpenStack.git
cd Automated-Multi-Tenant-OpenStack

# Install required tools
sudo apt update
sudo apt install -y python3-pip terraform ansible

# Install Python dependencies
pip3 install -r requirements.txt

# Install Ansible collections
ansible-galaxy collection install openstack.cloud
ansible-galaxy collection install community.general
```

### 2. Configuration Setup

```bash
# Copy and customize configuration files
cp config/environments/production.yml.example config/environments/production.yml
cp config/terraform.tfvars.example config/terraform.tfvars
cp config/secrets/secrets.yml.example config/secrets/secrets.yml

# Edit configuration files with your specific values
vim config/environments/production.yml
vim config/terraform.tfvars
```

**Security Checklist:**
- [ ] All credentials moved to Ansible Vault
- [ ] SSH hardening applied (key-based auth only)
- [ ] Firewall configured with default deny policy
- [ ] TLS 1.3 enforced for all services
- [ ] API rate limiting configured
- [ ] Audit logging enabled with 7-year retention
- [ ] File integrity monitoring active
- [ ] Automatic security updates configured
- [ ] Intrusion detection system operational

### 4. Secret Management

```bash
# Create Ansible vault for secrets
ansible-vault create config/secrets/vault.yml

# Add the following secrets to vault.yml:
# vault_mysql_root_password: "secure_password"
# vault_keystone_admin_password: "secure_password"
# vault_service_passwords: {...}
# vault_ssl_certificates: {...}

# Create vault password file (store securely)
echo "your_vault_password" > .vault_pass
chmod 600 .vault_pass
```

## Deployment Steps

### Phase 1: Infrastructure Deployment

#### 1. Initialize Terraform

```bash
cd terraform/
terraform init

# Plan the deployment
terraform plan -var-file="../config/terraform.tfvars"

# Apply the infrastructure
terraform apply -var-file="../config/terraform.tfvars"
```

#### 2. Generate Inventory

```bash
# Extract Terraform outputs to generate Ansible inventory
terraform output -json > terraform-outputs.json

# Generate inventory from Terraform outputs
python3 ../scripts/generate-inventory.py terraform-outputs.json > ../ansible/inventory/production
```

### Phase 2: OpenStack Configuration

#### 1. Prepare Nodes

```bash
cd ../ansible/

# Test connectivity to all nodes
ansible all -i inventory/production -m ping

# Update all nodes
ansible all -i inventory/production -m apt -a "update_cache=yes upgrade=yes" --become
```

#### 2. Deploy OpenStack

```bash
# Run the main playbook
ansible-playbook -i inventory/production site.yml

# Monitor deployment progress
tail -f ansible.log
```

#### 3. Verify Services

```bash
# Check service status
ansible controllers -i inventory/production -m shell -a "systemctl status apache2 mysql rabbitmq-server memcached"

# Verify OpenStack services
ansible controllers[0] -i inventory/production -m shell -a "source /root/admin-openrc && openstack service list"
```

### Phase 3: Multi-Tenant Setup

#### 1. Configure Initial Tenants

```bash
# Create tenant configuration
cat > config/tenant-config.yml << EOF
tenants:
  - name: "tenant-development"
    description: "Development Environment"
    admin_user:
      username: "dev-admin"
      password: "secure_password"
      email: "dev-admin@company.com"
    quotas:
      compute:
        instances: 10
        cores: 20
        ram: 40960
      volume:
        volumes: 10
        gigabytes: 500
    users:
      - username: "dev-user1"
        password: "secure_password"
        role: "member"
      - username: "dev-user2"
        password: "secure_password"
        role: "member"
  
  - name: "tenant-staging"
    description: "Staging Environment"
    admin_user:
      username: "stage-admin"
      password: "secure_password"
      email: "stage-admin@company.com"
    quotas:
      compute:
        instances: 15
        cores: 30
        ram: 61440
      volume:
        volumes: 15
        gigabytes: 750
  
  - name: "tenant-production"
    description: "Production Environment"
    admin_user:
      username: "prod-admin"
      password: "secure_password"
      email: "prod-admin@company.com"
    quotas:
      compute:
        instances: 50
        cores: 100
        ram: 204800
      volume:
        volumes: 50
        gigabytes: 2000
EOF

# Run tenant onboarding
ansible-playbook -i inventory/production playbooks/tenant-onboarding.yml \
  -e tenant_config=tenant-config.yml
```

#### 2. Verify Tenant Isolation

```bash
# Run validation script
python3 tests/validation/validate-environment.py \
  --config config/validation-config.yml \
  --output validation-results.json
```

### Phase 4: Billing Integration

#### 1. Configure CloudKitty

```bash
# Deploy billing infrastructure
ansible-playbook -i inventory/production playbooks/setup-billing.yml

# Initialize CloudKitty database
ansible billing -i inventory/production -m shell -a "cloudkitty-dbsync upgrade"

# Start CloudKitty services
ansible billing -i inventory/production -m systemd -a "name=cloudkitty-api state=started enabled=yes"
ansible billing -i inventory/production -m systemd -a "name=cloudkitty-processor state=started enabled=yes"
```

#### 2. Configure Pricing

```bash
# Set up pricing rules
ansible controllers[0] -i inventory/production -m shell -a "
source /root/admin-openrc &&
cloudkitty hashmap service create compute &&
cloudkitty hashmap field create compute flavor_id &&
cloudkitty hashmap mapping create flavor_id m1.small 0.05
"
```

### Phase 5: Monitoring Setup

#### 1. Deploy Monitoring Stack

```bash
# Deploy monitoring infrastructure
ansible-playbook -i inventory/production playbooks/setup-monitoring.yml

# Import Grafana dashboards
curl -X POST http://monitoring-node:3000/api/dashboards/db \
  -H "Content-Type: application/json" \
  -d @monitoring/grafana/dashboards/openstack-multi-tenant.json
```

## Post-Deployment Configuration

### 1. SSL Certificate Setup

```bash
# Generate or install SSL certificates
ansible controllers -i inventory/production -m copy -a "
src=ssl/openstack.crt
dest=/etc/ssl/certs/openstack.crt
mode=0644
"

ansible controllers -i inventory/production -m copy -a "
src=ssl/openstack.key
dest=/etc/ssl/private/openstack.key
mode=0600
"

# Restart services to use SSL
ansible controllers -i inventory/production -m systemd -a "
name=apache2
state=restarted
"
```

### 2. High Availability (Optional)

```bash
# If HA is enabled, configure load balancer
ansible-playbook -i inventory/production playbooks/setup-ha.yml
```

### 3. Backup Configuration

```bash
# Set up automated backups
ansible-playbook -i inventory/production playbooks/setup-backup.yml
```

## Validation and Testing

### 1. Service Validation

```bash
# Validate all services
python3 tests/validation/validate-environment.py

# Test tenant operations
ansible-playbook -i inventory/production playbooks/test-tenant-operations.yml
```

### 2. RBAC Testing

```bash
# Test RBAC policies
python3 tests/integration/test-rbac.py

# Test unauthorized access attempts
python3 tests/security/test-access-control.py
```

### 3. Billing Validation

```bash
# Generate test billing report
python3 scripts/billing/generate-billing-report.py \
  --start-date 2025-01-01 \
  --end-date 2025-01-31 \
  --format json
```

## Maintenance and Operations

### Daily Operations

1. **Monitor Service Health**
   ```bash
   ansible all -i inventory/production -m shell -a "systemctl status openstack-*"
   ```

2. **Check Resource Usage**
   ```bash
   python3 scripts/monitoring/check-resource-usage.py
   ```

3. **Review Logs**
   ```bash
   ansible controllers -i inventory/production -m shell -a "journalctl -u apache2 -f"
   ```

### Weekly Operations

1. **Generate Billing Reports**
   ```bash
   python3 scripts/billing/generate-weekly-report.py
   ```

2. **Update Security Patches**
   ```bash
   ansible all -i inventory/production -m apt -a "update_cache=yes upgrade=yes"
   ```

3. **Backup Configuration**
   ```bash
   ansible-playbook -i inventory/production playbooks/backup-config.yml
   ```

### Monthly Operations

1. **Tenant Usage Review**
   ```bash
   python3 scripts/reporting/tenant-usage-analysis.py
   ```

2. **Capacity Planning**
   ```bash
   python3 scripts/monitoring/capacity-planning.py
   ```

3. **Security Audit**
   ```bash
   python3 tests/security/security-audit.py
   ```

## Troubleshooting

### Common Issues

#### 1. Service Startup Failures

```bash
# Check service logs
ansible controllers -i inventory/production -m shell -a "journalctl -u openstack-nova-api -n 50"

# Restart services
ansible controllers -i inventory/production -m systemd -a "name=openstack-nova-api state=restarted"
```

#### 2. Database Connection Issues

```bash
# Check database status
ansible controllers -i inventory/production -m shell -a "systemctl status mysql"

# Test database connectivity
ansible controllers -i inventory/production -m shell -a "mysql -u root -p -e 'SHOW DATABASES;'"
```

#### 3. Network Connectivity Issues

```bash
# Test network connectivity
ansible all -i inventory/production -m shell -a "ping -c 3 {{ management_ip }}"

# Check network configuration
ansible all -i inventory/production -m shell -a "ip addr show"
```

### Log Locations

- **Nova**: `/var/log/nova/`
- **Neutron**: `/var/log/neutron/`
- **Keystone**: `/var/log/keystone/`
- **Horizon**: `/var/log/apache2/`
- **CloudKitty**: `/var/log/cloudkitty/`

## Scaling Considerations

### Adding Compute Nodes

1. Update Terraform configuration
2. Apply infrastructure changes
3. Update Ansible inventory
4. Run compute node playbook

### Upgrading OpenStack

1. Review upgrade documentation
2. Backup configuration and data
3. Test upgrade in staging environment
4. Perform rolling upgrade

## Security Best Practices

1. **Regular Security Updates**
2. **Strong Password Policies**
3. **SSL/TLS Encryption**
4. **Network Segmentation**
5. **Regular Security Audits**
6. **Backup and Disaster Recovery**

## Support and Documentation

- [OpenStack Documentation](https://docs.openstack.org/)
- [Ansible Documentation](https://docs.ansible.com/)
- [Terraform Documentation](https://www.terraform.io/docs/)
- [Project GitHub Repository](https://github.com/ruslanbaba/Automated-Multi-Tenant-OpenStack)
