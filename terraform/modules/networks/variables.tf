variable "project_name" {
  description = "Name of the project for resource naming"
  type        = string
}

variable "external_network_id" {
  description = "ID of the external network"
  type        = string
}

variable "management_network_cidr" {
  description = "CIDR for management network"
  type        = string
}

variable "api_network_cidr" {
  description = "CIDR for API network"
  type        = string
}

variable "storage_network_cidr" {
  description = "CIDR for storage network"
  type        = string
}

variable "tenant_network_cidr" {
  description = "CIDR for tenant network"
  type        = string
}

variable "dns_nameservers" {
  description = "List of DNS nameservers"
  type        = list(string)
  default     = ["8.8.8.8", "8.8.4.4"]
}
