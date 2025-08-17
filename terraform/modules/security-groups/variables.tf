variable "project_name" {
  description = "Name of the project for resource naming"
  type        = string
}

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

variable "management_cidr" {
  description = "CIDR block for management network"
  type        = string
}

variable "storage_cidr" {
  description = "CIDR block for storage network"
  type        = string
}
