# Variables for OpenStack Multi-Tenant Environment

variable "project_name" {
  description = "Name of the project for resource naming"
  type        = string
  default     = "openstack-multi-tenant"
}

variable "openstack_auth_url" {
  description = "OpenStack authentication URL"
  type        = string
}

variable "openstack_region" {
  description = "OpenStack region"
  type        = string
  default     = "RegionOne"
}

variable "admin_tenant_name" {
  description = "Admin tenant name"
  type        = string
  default     = "admin"
}

variable "admin_username" {
  description = "Admin username"
  type        = string
  default     = "admin"
}

variable "admin_password" {
  description = "Admin password"
  type        = string
  sensitive   = true
}

variable "base_image_name" {
  description = "Base image name for instances"
  type        = string
  default     = "ubuntu-22.04-server-cloudimg-amd64"
}

variable "external_network_name" {
  description = "Name of the external network"
  type        = string
  default     = "public"
}

variable "availability_zones" {
  description = "List of availability zones"
  type        = list(string)
  default     = ["nova"]
}

# Controller Configuration
variable "controller_count" {
  description = "Number of controller nodes"
  type        = number
  default     = 1
}

variable "controller_flavor" {
  description = "Flavor for controller nodes"
  type        = string
  default     = "m1.xlarge"
}

variable "controller_volume_size" {
  description = "Size of controller node volumes in GB"
  type        = number
  default     = 100
}

# Compute Configuration
variable "compute_count" {
  description = "Number of compute nodes"
  type        = number
  default     = 2
}

variable "compute_flavor" {
  description = "Flavor for compute nodes"
  type        = string
  default     = "m1.large"
}

variable "compute_volume_size" {
  description = "Size of compute node volumes in GB"
  type        = number
  default     = 50
}

# Storage Configuration
variable "volume_type" {
  description = "Type of volumes to create"
  type        = string
  default     = "standard"
}

# Network Configuration
variable "management_network_cidr" {
  description = "CIDR for management network"
  type        = string
  default     = "10.0.0.0/24"
}

variable "api_network_cidr" {
  description = "CIDR for API network"
  type        = string
  default     = "10.0.1.0/24"
}

variable "storage_network_cidr" {
  description = "CIDR for storage network"
  type        = string
  default     = "10.0.2.0/24"
}

variable "tenant_network_cidr" {
  description = "CIDR for tenant network"
  type        = string
  default     = "10.0.3.0/24"
}

variable "dns_nameservers" {
  description = "List of DNS nameservers"
  type        = list(string)
  default     = ["8.8.8.8", "8.8.4.4"]
}

# Security Configuration
variable "allowed_ssh_cidrs" {
  description = "List of CIDRs allowed for SSH access"
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "allowed_api_cidrs" {
  description = "List of CIDRs allowed for API access"
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

# High Availability Configuration
variable "enable_ha" {
  description = "Enable high availability setup"
  type        = bool
  default     = false
}

variable "vip_address" {
  description = "Virtual IP address for HA setup"
  type        = string
  default     = "10.0.1.100"
}

# Monitoring Configuration
variable "enable_monitoring" {
  description = "Enable monitoring infrastructure"
  type        = bool
  default     = true
}

variable "monitoring_flavor" {
  description = "Flavor for monitoring nodes"
  type        = string
  default     = "m1.medium"
}

# Billing Configuration
variable "billing_flavor" {
  description = "Flavor for billing nodes"
  type        = string
  default     = "m1.small"
}

# DNS Configuration
variable "enable_dns" {
  description = "Enable DNS record creation"
  type        = bool
  default     = false
}

variable "dns_zone_id" {
  description = "DNS zone ID for record creation"
  type        = string
  default     = ""
}

variable "dns_domain" {
  description = "DNS domain for record creation"
  type        = string
  default     = "example.com"
}

# SSL Configuration
variable "enable_ssl" {
  description = "Enable SSL/TLS encryption"
  type        = bool
  default     = true
}

variable "ssl_cert_path" {
  description = "Path to SSL certificate"
  type        = string
  default     = "/etc/ssl/certs/openstack.crt"
}

variable "ssl_key_path" {
  description = "Path to SSL private key"
  type        = string
  default     = "/etc/ssl/private/openstack.key"
}

# Tags
variable "common_tags" {
  description = "Common tags to apply to all resources"
  type        = map(string)
  default = {
    Environment = "production"
    Project     = "openstack-multi-tenant"
    Terraform   = "true"
  }
}

# Tenant Configuration
variable "default_tenant_quotas" {
  description = "Default quotas for new tenants"
  type = object({
    instances = number
    cores     = number
    ram       = number
    volumes   = number
    gigabytes = number
    networks  = number
    routers   = number
  })
  default = {
    instances = 10
    cores     = 20
    ram       = 51200
    volumes   = 10
    gigabytes = 1000
    networks  = 10
    routers   = 10
  }
}
