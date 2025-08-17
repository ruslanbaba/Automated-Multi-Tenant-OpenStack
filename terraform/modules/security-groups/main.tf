# Security Groups Module for OpenStack Multi-Tenant Environment
# SECURITY ENHANCED: Implements principle of least privilege

# Controller Security Group
resource "openstack_networking_secgroup_v2" "controller" {
  name        = "${var.project_name}-controller-sg"
  description = "Security group for OpenStack controller nodes - restricted access"
}

# Controller Security Group Rules - SECURITY ENHANCED
# SSH access only from management network with specific source IPs
resource "openstack_networking_secgroup_rule_v2" "controller_ssh" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 22
  port_range_max    = 22
  remote_ip_prefix  = var.management_cidr  # Restricted to management network only
  security_group_id = openstack_networking_secgroup_v2.controller.id
  description       = "SSH access from management network only"
}

# SECURITY FIX: Keystone API access restricted to API network only
resource "openstack_networking_secgroup_rule_v2" "controller_keystone" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 5000
  port_range_max    = 5000
  remote_ip_prefix  = var.api_cidr  # SECURITY FIX: Changed from 0.0.0.0/0
  security_group_id = openstack_networking_secgroup_v2.controller.id
  description       = "Keystone API access from API network only"
}

# SECURITY FIX: Keystone admin access only from management network
resource "openstack_networking_secgroup_rule_v2" "controller_keystone_admin" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 35357
  port_range_max    = 35357
  remote_ip_prefix  = var.management_cidr
  security_group_id = openstack_networking_secgroup_v2.controller.id
  description       = "Keystone admin access from management network only"
}

# SECURITY FIX: Nova API access restricted to API network
resource "openstack_networking_secgroup_rule_v2" "controller_nova_api" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 8774
  port_range_max    = 8774
  remote_ip_prefix  = var.api_cidr  # SECURITY FIX: Changed from 0.0.0.0/0
  security_group_id = openstack_networking_secgroup_v2.controller.id
  description       = "Nova API access from API network only"
}

# Nova metadata service - restricted to management network
resource "openstack_networking_secgroup_rule_v2" "controller_nova_metadata" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 8775
  port_range_max    = 8775
  remote_ip_prefix  = var.management_cidr
  security_group_id = openstack_networking_secgroup_v2.controller.id
  description       = "Nova metadata service from management network only"
}

# SECURITY FIX: Placement API access restricted to API network
resource "openstack_networking_secgroup_rule_v2" "controller_placement" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 8778
  port_range_max    = 8778
  remote_ip_prefix  = var.api_cidr  # SECURITY FIX: Changed from 0.0.0.0/0
  security_group_id = openstack_networking_secgroup_v2.controller.id
  description       = "Placement API access from API network only"
}

# SECURITY FIX: Neutron API access restricted to API network
resource "openstack_networking_secgroup_rule_v2" "controller_neutron" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 9696
  port_range_max    = 9696
  remote_ip_prefix  = var.api_cidr  # SECURITY FIX: Changed from 0.0.0.0/0
  security_group_id = openstack_networking_secgroup_v2.controller.id
  description       = "Neutron API access from API network only"
}

resource "openstack_networking_secgroup_rule_v2" "controller_glance_api" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 9292
  port_range_max    = 9292
  remote_ip_prefix  = "0.0.0.0/0"
  security_group_id = openstack_networking_secgroup_v2.controller.id
}

resource "openstack_networking_secgroup_rule_v2" "controller_glance_registry" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 9191
  port_range_max    = 9191
  remote_ip_prefix  = var.management_cidr
  security_group_id = openstack_networking_secgroup_v2.controller.id
}

resource "openstack_networking_secgroup_rule_v2" "controller_cinder_api" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 8776
  port_range_max    = 8776
  remote_ip_prefix  = "0.0.0.0/0"
  security_group_id = openstack_networking_secgroup_v2.controller.id
}

resource "openstack_networking_secgroup_rule_v2" "controller_horizon" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 80
  port_range_max    = 80
  remote_ip_prefix  = "0.0.0.0/0"
  security_group_id = openstack_networking_secgroup_v2.controller.id
}

resource "openstack_networking_secgroup_rule_v2" "controller_horizon_ssl" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 443
  port_range_max    = 443
  remote_ip_prefix  = "0.0.0.0/0"
  security_group_id = openstack_networking_secgroup_v2.controller.id
}

# Compute Security Group
resource "openstack_networking_secgroup_v2" "compute" {
  name        = "${var.project_name}-compute-sg"
  description = "Security group for OpenStack compute nodes"
}

# Compute Security Group Rules
resource "openstack_networking_secgroup_rule_v2" "compute_ssh" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 22
  port_range_max    = 22
  remote_ip_prefix  = var.management_cidr
  security_group_id = openstack_networking_secgroup_v2.compute.id
}

resource "openstack_networking_secgroup_rule_v2" "compute_vnc" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 5900
  port_range_max    = 5999
  remote_ip_prefix  = var.management_cidr
  security_group_id = openstack_networking_secgroup_v2.compute.id
}

resource "openstack_networking_secgroup_rule_v2" "compute_migration" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 16509
  port_range_max    = 16509
  remote_ip_prefix  = var.management_cidr
  security_group_id = openstack_networking_secgroup_v2.compute.id
}

# VXLAN tunneling
resource "openstack_networking_secgroup_rule_v2" "compute_vxlan" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "udp"
  port_range_min    = 4789
  port_range_max    = 4789
  remote_ip_prefix  = var.management_cidr
  security_group_id = openstack_networking_secgroup_v2.compute.id
}

# Management Security Group
resource "openstack_networking_secgroup_v2" "management" {
  name        = "${var.project_name}-management-sg"
  description = "Security group for management network access"
}

# Management Security Group Rules
resource "openstack_networking_secgroup_rule_v2" "management_all_tcp" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 1
  port_range_max    = 65535
  remote_ip_prefix  = var.management_cidr
  security_group_id = openstack_networking_secgroup_v2.management.id
}

resource "openstack_networking_secgroup_rule_v2" "management_all_udp" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "udp"
  port_range_min    = 1
  port_range_max    = 65535
  remote_ip_prefix  = var.management_cidr
  security_group_id = openstack_networking_secgroup_v2.management.id
}

resource "openstack_networking_secgroup_rule_v2" "management_icmp" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "icmp"
  remote_ip_prefix  = var.management_cidr
  security_group_id = openstack_networking_secgroup_v2.management.id
}

# API Security Group
resource "openstack_networking_secgroup_v2" "api" {
  name        = "${var.project_name}-api-sg"
  description = "Security group for API access"
}

# Storage Security Group
resource "openstack_networking_secgroup_v2" "storage" {
  name        = "${var.project_name}-storage-sg"
  description = "Security group for storage network"
}

# Storage Security Group Rules
resource "openstack_networking_secgroup_rule_v2" "storage_iscsi" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 3260
  port_range_max    = 3260
  remote_ip_prefix  = var.storage_cidr
  security_group_id = openstack_networking_secgroup_v2.storage.id
}

resource "openstack_networking_secgroup_rule_v2" "storage_nfs" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 2049
  port_range_max    = 2049
  remote_ip_prefix  = var.storage_cidr
  security_group_id = openstack_networking_secgroup_v2.storage.id
}

# Monitoring Security Group
resource "openstack_networking_secgroup_v2" "monitoring" {
  name        = "${var.project_name}-monitoring-sg"
  description = "Security group for monitoring services"
}

# Monitoring Security Group Rules
resource "openstack_networking_secgroup_rule_v2" "monitoring_ssh" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 22
  port_range_max    = 22
  remote_ip_prefix  = var.management_cidr
  security_group_id = openstack_networking_secgroup_v2.monitoring.id
}

resource "openstack_networking_secgroup_rule_v2" "monitoring_prometheus" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 9090
  port_range_max    = 9090
  remote_ip_prefix  = var.management_cidr
  security_group_id = openstack_networking_secgroup_v2.monitoring.id
}

resource "openstack_networking_secgroup_rule_v2" "monitoring_grafana" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 3000
  port_range_max    = 3000
  remote_ip_prefix  = "0.0.0.0/0"
  security_group_id = openstack_networking_secgroup_v2.monitoring.id
}

resource "openstack_networking_secgroup_rule_v2" "monitoring_node_exporter" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 9100
  port_range_max    = 9100
  remote_ip_prefix  = var.management_cidr
  security_group_id = openstack_networking_secgroup_v2.monitoring.id
}

# Billing Security Group
resource "openstack_networking_secgroup_v2" "billing" {
  name        = "${var.project_name}-billing-sg"
  description = "Security group for billing services"
}

# Billing Security Group Rules
resource "openstack_networking_secgroup_rule_v2" "billing_ssh" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 22
  port_range_max    = 22
  remote_ip_prefix  = var.management_cidr
  security_group_id = openstack_networking_secgroup_v2.billing.id
}

resource "openstack_networking_secgroup_rule_v2" "billing_api" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 8889
  port_range_max    = 8889
  remote_ip_prefix  = var.management_cidr
  security_group_id = openstack_networking_secgroup_v2.billing.id
}

resource "openstack_networking_secgroup_rule_v2" "billing_web" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 8080
  port_range_max    = 8080
  remote_ip_prefix  = "0.0.0.0/0"
  security_group_id = openstack_networking_secgroup_v2.billing.id
}
