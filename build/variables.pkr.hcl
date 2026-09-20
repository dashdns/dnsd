// Input variables for the dnsd AMI build.
//
// Override with a *.auto.pkrvars.hcl file (see dnsd.auto.pkrvars.hcl.example),
// with -var 'name=value', or with PKR_VAR_<name> environment variables.

variable "region" {
  type        = string
  default     = "eu-central-1"
  description = "AWS region to build the AMI in."
}

variable "ami_regions" {
  type        = list(string)
  default     = []
  description = "Additional regions to copy the finished AMI to."
}

variable "ami_users" {
  type        = list(string)
  default     = []
  description = "AWS account IDs allowed to launch the resulting AMI."
}

variable "ami_name_prefix" {
  type        = string
  default     = "dnsd"
  description = "Prefix for the produced AMI name. The suffix is <arch>-<version>-<timestamp>."
}

variable "dnsd_version" {
  type        = string
  default     = "dev"
  description = "Version stamped into the AMI name and /etc/dnsd-release. Usually the git tag."
}

// ---------------------------------------------------------------------------
// Base image
// ---------------------------------------------------------------------------

variable "base_ami_owner" {
  type        = string
  default     = "099720109477"
  description = "AWS account that owns the base AMIs. 099720109477 is Canonical."
}

variable "source_ami_filter_amd64" {
  type        = string
  default     = "ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*"
  description = "Name filter used to find the newest Ubuntu 24.04 amd64 base AMI."
}

variable "source_ami_filter_arm64" {
  type        = string
  default     = "ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-arm64-server-*"
  description = "Name filter used to find the newest Ubuntu 24.04 arm64 base AMI."
}

variable "ssh_username" {
  type        = string
  default     = "ubuntu"
  description = "Login user on the official Ubuntu AMIs (Debian AMIs use 'admin')."
}

variable "root_device_name" {
  type        = string
  default     = "/dev/sda1"
  description = <<-EOT
    Root block device of the base AMI. Ubuntu uses /dev/sda1; Debian uses
    /dev/xvda. Getting this wrong makes Packer attach a second volume instead
    of resizing the root one.
  EOT
}

// ---------------------------------------------------------------------------
// Build instance
// ---------------------------------------------------------------------------

variable "instance_type_amd64" {
  type        = string
  default     = "c6i.xlarge"
  description = "Build instance type for amd64. Must be ENA-capable so NIC tuning can be validated."
}

variable "instance_type_arm64" {
  type        = string
  default     = "c7g.xlarge"
  description = "Build instance type for arm64. Must be ENA-capable so NIC tuning can be validated."
}

variable "volume_size" {
  type        = number
  default     = 10
  description = "Root EBS volume size in GiB for the produced AMI."
}

variable "volume_type" {
  type        = string
  default     = "gp3"
  description = "Root EBS volume type."
}

variable "vpc_id" {
  type        = string
  default     = ""
  description = "VPC to launch the build instance in. Empty uses the account default VPC."
}

variable "subnet_id" {
  type        = string
  default     = ""
  description = "Subnet to launch the build instance in. Empty lets Packer pick one."
}

variable "associate_public_ip_address" {
  type        = bool
  default     = true
  description = "Set false when building in a private subnet reachable over a VPN/Direct Connect."
}

variable "ssh_interface" {
  type        = string
  default     = "public_ip"
  description = "How Packer reaches the build instance: public_ip, private_ip, or session_manager."
}

variable "iam_instance_profile" {
  type        = string
  default     = ""
  description = "Instance profile for the builder. Required when ssh_interface = session_manager."
}

// ---------------------------------------------------------------------------
// Toolchain
// ---------------------------------------------------------------------------

variable "go_version" {
  type        = string
  default     = "1.25.6"
  description = "Go toolchain downloaded from go.dev. Must satisfy the 'go' directive in go.mod."
}

variable "llvm_version" {
  type        = string
  default     = "18"
  description = "clang/LLVM major version used to compile bpf/xdp_tc.c. Ubuntu 24.04 ships 18; Debian 13 ships 19."
}

// ---------------------------------------------------------------------------
// Image slimming
// ---------------------------------------------------------------------------

variable "strip_kernel_modules" {
  type        = bool
  default     = true
  description = <<-EOT
    Physically delete unused kernel module trees (sound, wireless, bluetooth,
    infiniband, media, gpu, ...) from /lib/modules and rerun depmod. Storage and
    networking modules are never touched. Set false to keep blacklisting only.
  EOT
}

variable "purge_packages" {
  type        = bool
  default     = true
  description = "Purge redundant base packages (mail, wireless, docs, locales, ...)."
}

variable "debug_password" {
  type        = string
  default     = ""
  sensitive   = true
  description = <<-EOT
    Sets a console password for the ssh_username account so the EC2 serial
    console can be used when sshd will not start. Empty (the default) leaves
    the account locked, as Debian ships it.

    DEBUGGING ONLY. An image built with this set is marked with
    /etc/dnsd-DEBUG-IMAGE and must never be promoted to production.
  EOT
}

variable "disable_unattended_upgrades" {
  type        = bool
  default     = true
  description = <<-EOT
    Disable unattended-upgrades. Correct for an immutable appliance image that is
    rebaked to pick up patches; set false if the fleet patches in place instead.
  EOT
}

// ---------------------------------------------------------------------------
// Baked-in dnsd defaults (written to /etc/default/dnsd; override per instance
// via cloud-init user-data)
// ---------------------------------------------------------------------------

variable "dnsd_iface" {
  type        = string
  default     = "ens5"
  description = "Default interface for XDP/TC attachment. ENA NICs are ens5/ens6/... on Nitro."
}

variable "dnsd_upstream" {
  type        = string
  default     = "169.254.169.253:53"
  description = "Default upstream resolver. 169.254.169.253 is the AWS VPC resolver."
}

variable "dnsd_link_mode" {
  type        = string
  default     = "driver"
  description = "XDP attach mode: generic (SKB), driver (native, supported by ENA), or offload."

  validation {
    condition     = contains(["generic", "driver", "offload"], var.dnsd_link_mode)
    error_message = "The dnsd_link_mode value must be one of: generic, driver, offload."
  }
}

variable "dnsd_ipam" {
  type        = string
  default     = "onpremise"
  description = <<-EOT
    IPAM mode. 'onpremise' attaches to dnsd_iface only. 'aws-vpc-cni' scans for
    ens* interfaces at startup and watches netlink for new ENIs.
  EOT

  validation {
    condition     = contains(["onpremise", "aws-vpc-cni"], var.dnsd_ipam)
    error_message = "The dnsd_ipam value must be one of: onpremise, aws-vpc-cni."
  }
}
