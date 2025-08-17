# Outputs for OpenStack Multi-Tenant Environment

# Network Outputs
output "management_network_id" {
  description = "ID of the management network"
  value       = module.networks.management_network_id
}

output "api_network_id" {
  description = "ID of the API network"
  value       = module.networks.api_network_id
}

output "storage_network_id" {
  description = "ID of the storage network"
  value       = module.networks.storage_network_id
}

output "tenant_network_id" {
  description = "ID of the tenant network"
  value       = module.networks.tenant_network_id
}

# Controller Node Outputs
output "controller_instance_ids" {
  description = "IDs of controller instances"
  value       = module.controller.instance_ids
}

output "controller_private_ips" {
  description = "Private IP addresses of controller nodes"
  value       = module.controller.private_ips
}

output "controller_floating_ips" {
  description = "Floating IP addresses of controller nodes"
  value       = openstack_networking_floatingip_v2.controller_floating_ip[*].address
}

# Compute Node Outputs
output "compute_instance_ids" {
  description = "IDs of compute instances"
  value       = module.compute.instance_ids
}

output "compute_private_ips" {
  description = "Private IP addresses of compute nodes"
  value       = module.compute.private_ips
}

# Load Balancer Outputs (if HA is enabled)
output "load_balancer_vip" {
  description = "Load balancer VIP address"
  value       = var.enable_ha ? module.load_balancer[0].vip_address : null
}

output "load_balancer_floating_ip" {
  description = "Load balancer floating IP"
  value       = var.enable_ha ? module.load_balancer[0].floating_ip : null
}

# Monitoring Outputs (if enabled)
output "monitoring_instance_id" {
  description = "ID of monitoring instance"
  value       = var.enable_monitoring ? module.monitoring[0].instance_id : null
}

output "monitoring_private_ip" {
  description = "Private IP of monitoring instance"
  value       = var.enable_monitoring ? module.monitoring[0].private_ip : null
}

# Billing Outputs
output "billing_instance_id" {
  description = "ID of billing instance"
  value       = module.billing.instance_id
}

output "billing_private_ip" {
  description = "Private IP of billing instance"
  value       = module.billing.private_ip
}

# Security Group Outputs
output "controller_security_group_id" {
  description = "ID of controller security group"
  value       = module.security_groups.controller_security_group_id
}

output "compute_security_group_id" {
  description = "ID of compute security group"
  value       = module.security_groups.compute_security_group_id
}

output "management_security_group_id" {
  description = "ID of management security group"
  value       = module.security_groups.management_security_group_id
}

# SSH Key Outputs
output "ssh_private_key" {
  description = "Private SSH key for accessing instances"
  value       = tls_private_key.ssh_key.private_key_pem
  sensitive   = true
}

output "ssh_public_key" {
  description = "Public SSH key"
  value       = tls_private_key.ssh_key.public_key_openssh
}

output "keypair_name" {
  description = "Name of the created keypair"
  value       = openstack_compute_keypair_v2.main.name
}

# OpenStack Endpoints
output "openstack_endpoints" {
  description = "OpenStack service endpoints"
  value = {
    identity     = var.enable_ha ? "https://${var.vip_address}:5000/v3" : "https://${openstack_networking_floatingip_v2.controller_floating_ip[0].address}:5000/v3"
    compute      = var.enable_ha ? "https://${var.vip_address}:8774/v2.1" : "https://${openstack_networking_floatingip_v2.controller_floating_ip[0].address}:8774/v2.1"
    network      = var.enable_ha ? "https://${var.vip_address}:9696" : "https://${openstack_networking_floatingip_v2.controller_floating_ip[0].address}:9696"
    volume       = var.enable_ha ? "https://${var.vip_address}:8776/v3" : "https://${openstack_networking_floatingip_v2.controller_floating_ip[0].address}:8776/v3"
    image        = var.enable_ha ? "https://${var.vip_address}:9292" : "https://${openstack_networking_floatingip_v2.controller_floating_ip[0].address}:9292"
    dashboard    = var.enable_ha ? "https://${var.vip_address}/horizon" : "https://${openstack_networking_floatingip_v2.controller_floating_ip[0].address}/horizon"
  }
}

# DNS Records (if enabled)
output "dns_records" {
  description = "Created DNS records"
  value = var.enable_dns ? {
    controllers = openstack_dns_recordset_v2.controller_dns[*].name
    api_vip     = var.enable_ha ? openstack_dns_recordset_v2.ha_vip_dns[0].name : null
  } : null
}

# Ansible Inventory Information
output "ansible_inventory" {
  description = "Ansible inventory information"
  value = {
    controllers = {
      for i in range(var.controller_count) : "controller-${i + 1}" => {
        ansible_host         = openstack_networking_floatingip_v2.controller_floating_ip[i].address
        private_ip          = module.controller.private_ips[i]
        instance_id         = module.controller.instance_ids[i]
        ansible_user        = "ubuntu"
        ansible_ssh_private_key_file = "./ssh_key.pem"
      }
    }
    computes = {
      for i in range(var.compute_count) : "compute-${i + 1}" => {
        private_ip   = module.compute.private_ips[i]
        instance_id  = module.compute.instance_ids[i]
        ansible_user = "ubuntu"
        ansible_ssh_private_key_file = "./ssh_key.pem"
        ansible_ssh_common_args = "-o ProxyCommand='ssh -W %h:%p ubuntu@${openstack_networking_floatingip_v2.controller_floating_ip[0].address}'"
      }
    }
    monitoring = var.enable_monitoring ? {
      "monitoring-1" = {
        private_ip   = module.monitoring[0].private_ip
        instance_id  = module.monitoring[0].instance_id
        ansible_user = "ubuntu"
        ansible_ssh_private_key_file = "./ssh_key.pem"
        ansible_ssh_common_args = "-o ProxyCommand='ssh -W %h:%p ubuntu@${openstack_networking_floatingip_v2.controller_floating_ip[0].address}'"
      }
    } : {}
    billing = {
      "billing-1" = {
        private_ip   = module.billing.private_ip
        instance_id  = module.billing.instance_id
        ansible_user = "ubuntu"
        ansible_ssh_private_key_file = "./ssh_key.pem"
        ansible_ssh_common_args = "-o ProxyCommand='ssh -W %h:%p ubuntu@${openstack_networking_floatingip_v2.controller_floating_ip[0].address}'"
      }
    }
  }
}

# Environment Information
output "environment_info" {
  description = "Environment configuration summary"
  value = {
    project_name       = var.project_name
    region             = var.openstack_region
    controller_count   = var.controller_count
    compute_count      = var.compute_count
    ha_enabled         = var.enable_ha
    monitoring_enabled = var.enable_monitoring
    ssl_enabled        = var.enable_ssl
    external_network   = var.external_network_name
  }
}
