output "management_network_id" {
  description = "ID of the management network"
  value       = openstack_networking_network_v2.management.id
}

output "management_subnet_id" {
  description = "ID of the management subnet"
  value       = openstack_networking_subnet_v2.management.id
}

output "api_network_id" {
  description = "ID of the API network"
  value       = openstack_networking_network_v2.api.id
}

output "api_subnet_id" {
  description = "ID of the API subnet"
  value       = openstack_networking_subnet_v2.api.id
}

output "storage_network_id" {
  description = "ID of the storage network"
  value       = openstack_networking_network_v2.storage.id
}

output "storage_subnet_id" {
  description = "ID of the storage subnet"
  value       = openstack_networking_subnet_v2.storage.id
}

output "tenant_network_id" {
  description = "ID of the tenant network"
  value       = openstack_networking_network_v2.tenant.id
}

output "tenant_subnet_id" {
  description = "ID of the tenant subnet"
  value       = openstack_networking_subnet_v2.tenant.id
}

output "router_id" {
  description = "ID of the main router"
  value       = openstack_networking_router_v2.main.id
}
