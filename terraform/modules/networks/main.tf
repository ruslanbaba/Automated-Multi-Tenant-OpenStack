# Networks Module for OpenStack Multi-Tenant Environment

# Management Network
resource "openstack_networking_network_v2" "management" {
  name           = "${var.project_name}-management"
  admin_state_up = "true"
  description    = "Management network for OpenStack infrastructure"
}

resource "openstack_networking_subnet_v2" "management" {
  name       = "${var.project_name}-management-subnet"
  network_id = openstack_networking_network_v2.management.id
  cidr       = var.management_network_cidr
  ip_version = 4
  dns_nameservers = var.dns_nameservers
  
  allocation_pool {
    start = cidrhost(var.management_network_cidr, 10)
    end   = cidrhost(var.management_network_cidr, 250)
  }
}

# API Network
resource "openstack_networking_network_v2" "api" {
  name           = "${var.project_name}-api"
  admin_state_up = "true"
  description    = "API network for OpenStack services"
}

resource "openstack_networking_subnet_v2" "api" {
  name       = "${var.project_name}-api-subnet"
  network_id = openstack_networking_network_v2.api.id
  cidr       = var.api_network_cidr
  ip_version = 4
  dns_nameservers = var.dns_nameservers
  
  allocation_pool {
    start = cidrhost(var.api_network_cidr, 10)
    end   = cidrhost(var.api_network_cidr, 250)
  }
}

# Storage Network
resource "openstack_networking_network_v2" "storage" {
  name           = "${var.project_name}-storage"
  admin_state_up = "true"
  description    = "Storage network for OpenStack storage services"
}

resource "openstack_networking_subnet_v2" "storage" {
  name       = "${var.project_name}-storage-subnet"
  network_id = openstack_networking_network_v2.storage.id
  cidr       = var.storage_network_cidr
  ip_version = 4
  dns_nameservers = var.dns_nameservers
  
  allocation_pool {
    start = cidrhost(var.storage_network_cidr, 10)
    end   = cidrhost(var.storage_network_cidr, 250)
  }
}

# Tenant Network
resource "openstack_networking_network_v2" "tenant" {
  name           = "${var.project_name}-tenant"
  admin_state_up = "true"
  description    = "Tenant network for OpenStack tenant traffic"
}

resource "openstack_networking_subnet_v2" "tenant" {
  name       = "${var.project_name}-tenant-subnet"
  network_id = openstack_networking_network_v2.tenant.id
  cidr       = var.tenant_network_cidr
  ip_version = 4
  dns_nameservers = var.dns_nameservers
  
  allocation_pool {
    start = cidrhost(var.tenant_network_cidr, 10)
    end   = cidrhost(var.tenant_network_cidr, 250)
  }
}

# Router for external connectivity
resource "openstack_networking_router_v2" "main" {
  name                = "${var.project_name}-router"
  admin_state_up      = true
  external_network_id = var.external_network_id
  description         = "Main router for OpenStack infrastructure"
}

# Router interfaces
resource "openstack_networking_router_interface_v2" "management" {
  router_id = openstack_networking_router_v2.main.id
  subnet_id = openstack_networking_subnet_v2.management.id
}

resource "openstack_networking_router_interface_v2" "api" {
  router_id = openstack_networking_router_v2.main.id
  subnet_id = openstack_networking_subnet_v2.api.id
}

resource "openstack_networking_router_interface_v2" "storage" {
  router_id = openstack_networking_router_v2.main.id
  subnet_id = openstack_networking_subnet_v2.storage.id
}

resource "openstack_networking_router_interface_v2" "tenant" {
  router_id = openstack_networking_router_v2.main.id
  subnet_id = openstack_networking_subnet_v2.tenant.id
}
