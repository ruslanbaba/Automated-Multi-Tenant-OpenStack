# Main Terraform configuration for OpenStack Multi-Tenant Environment
terraform {
  required_version = ">= 1.0"
  
  required_providers {
    openstack = {
      source  = "terraform-provider-openstack/openstack"
      version = "~> 1.54.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.4.0"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0.0"
    }
  }

  backend "s3" {
    bucket         = "openstack-terraform-state"
    key            = "openstack/terraform.tfstate"
    region         = "us-west-2"
    encrypt        = true
    dynamodb_table = "terraform-state-lock"
  }
}

# Configure the OpenStack Provider
provider "openstack" {
  auth_url    = var.openstack_auth_url
  region      = var.openstack_region
  tenant_name = var.admin_tenant_name
  user_name   = var.admin_username
  password    = var.admin_password
}

# Data sources
data "openstack_images_image_v2" "ubuntu" {
  name        = var.base_image_name
  most_recent = true
}

data "openstack_networking_network_v2" "external" {
  name     = var.external_network_name
  external = true
}

# Generate SSH key pair
resource "tls_private_key" "ssh_key" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "openstack_compute_keypair_v2" "main" {
  name       = "${var.project_name}-keypair"
  public_key = tls_private_key.ssh_key.public_key_openssh
}

# Security Groups
module "security_groups" {
  source = "./modules/security-groups"
  
  project_name          = var.project_name
  allowed_ssh_cidrs     = var.allowed_ssh_cidrs
  allowed_api_cidrs     = var.allowed_api_cidrs
  management_cidr       = var.management_network_cidr
  storage_cidr          = var.storage_network_cidr
}

# Networks
module "networks" {
  source = "./modules/networks"
  
  project_name            = var.project_name
  external_network_id     = data.openstack_networking_network_v2.external.id
  management_network_cidr = var.management_network_cidr
  api_network_cidr        = var.api_network_cidr
  storage_network_cidr    = var.storage_network_cidr
  tenant_network_cidr     = var.tenant_network_cidr
  dns_nameservers         = var.dns_nameservers
}

# Load Balancer for HA (if enabled)
module "load_balancer" {
  source = "./modules/load-balancer"
  count  = var.enable_ha ? 1 : 0
  
  project_name     = var.project_name
  subnet_id        = module.networks.api_subnet_id
  vip_address      = var.vip_address
  security_groups  = [module.security_groups.api_security_group_id]
}

# Controller Nodes
module "controller" {
  source = "./modules/controller"
  
  project_name        = var.project_name
  count               = var.controller_count
  flavor_name         = var.controller_flavor
  image_id            = data.openstack_images_image_v2.ubuntu.id
  key_pair_name       = openstack_compute_keypair_v2.main.name
  availability_zones  = var.availability_zones
  
  # Networks
  management_network_id = module.networks.management_network_id
  api_network_id        = module.networks.api_network_id
  storage_network_id    = module.networks.storage_network_id
  
  # Security Groups
  security_groups = [
    module.security_groups.controller_security_group_id,
    module.security_groups.management_security_group_id
  ]
  
  # Storage
  volume_size = var.controller_volume_size
  volume_type = var.volume_type
  
  # Load Balancer
  load_balancer_pool_id = var.enable_ha ? module.load_balancer[0].pool_id : null
}

# Compute Nodes
module "compute" {
  source = "./modules/compute"
  
  project_name        = var.project_name
  count               = var.compute_count
  flavor_name         = var.compute_flavor
  image_id            = data.openstack_images_image_v2.ubuntu.id
  key_pair_name       = openstack_compute_keypair_v2.main.name
  availability_zones  = var.availability_zones
  
  # Networks
  management_network_id = module.networks.management_network_id
  storage_network_id    = module.networks.storage_network_id
  tenant_network_id     = module.networks.tenant_network_id
  
  # Security Groups
  security_groups = [
    module.security_groups.compute_security_group_id,
    module.security_groups.management_security_group_id
  ]
  
  # Storage
  volume_size = var.compute_volume_size
  volume_type = var.volume_type
}

# Monitoring Infrastructure (if enabled)
module "monitoring" {
  source = "./modules/monitoring"
  count  = var.enable_monitoring ? 1 : 0
  
  project_name          = var.project_name
  flavor_name           = var.monitoring_flavor
  image_id              = data.openstack_images_image_v2.ubuntu.id
  key_pair_name         = openstack_compute_keypair_v2.main.name
  management_network_id = module.networks.management_network_id
  api_network_id        = module.networks.api_network_id
  
  security_groups = [
    module.security_groups.monitoring_security_group_id,
    module.security_groups.management_security_group_id
  ]
}

# Billing Infrastructure
module "billing" {
  source = "./modules/billing"
  
  project_name          = var.project_name
  flavor_name           = var.billing_flavor
  image_id              = data.openstack_images_image_v2.ubuntu.id
  key_pair_name         = openstack_compute_keypair_v2.main.name
  management_network_id = module.networks.management_network_id
  api_network_id        = module.networks.api_network_id
  
  security_groups = [
    module.security_groups.billing_security_group_id,
    module.security_groups.management_security_group_id
  ]
}

# Floating IPs for external access
resource "openstack_networking_floatingip_v2" "controller_floating_ip" {
  count = var.controller_count
  pool  = var.external_network_name
}

resource "openstack_compute_floatingip_associate_v2" "controller_floating_ip" {
  count       = var.controller_count
  floating_ip = openstack_networking_floatingip_v2.controller_floating_ip[count.index].address
  instance_id = module.controller.instance_ids[count.index]
}

# DNS Records (if DNS management is available)
resource "openstack_dns_recordset_v2" "controller_dns" {
  count   = var.enable_dns ? var.controller_count : 0
  zone_id = var.dns_zone_id
  name    = "controller-${count.index + 1}.${var.dns_domain}"
  type    = "A"
  records = [openstack_networking_floatingip_v2.controller_floating_ip[count.index].address]
  ttl     = 300
}

# HA VIP DNS Record
resource "openstack_dns_recordset_v2" "ha_vip_dns" {
  count   = var.enable_dns && var.enable_ha ? 1 : 0
  zone_id = var.dns_zone_id
  name    = "openstack-api.${var.dns_domain}"
  type    = "A"
  records = [var.vip_address]
  ttl     = 300
}
