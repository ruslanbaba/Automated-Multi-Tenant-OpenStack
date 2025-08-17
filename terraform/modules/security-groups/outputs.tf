output "controller_security_group_id" {
  description = "ID of the controller security group"
  value       = openstack_networking_secgroup_v2.controller.id
}

output "compute_security_group_id" {
  description = "ID of the compute security group"
  value       = openstack_networking_secgroup_v2.compute.id
}

output "management_security_group_id" {
  description = "ID of the management security group"
  value       = openstack_networking_secgroup_v2.management.id
}

output "api_security_group_id" {
  description = "ID of the API security group"
  value       = openstack_networking_secgroup_v2.api.id
}

output "storage_security_group_id" {
  description = "ID of the storage security group"
  value       = openstack_networking_secgroup_v2.storage.id
}

output "monitoring_security_group_id" {
  description = "ID of the monitoring security group"
  value       = openstack_networking_secgroup_v2.monitoring.id
}

output "billing_security_group_id" {
  description = "ID of the billing security group"
  value       = openstack_networking_secgroup_v2.billing.id
}
