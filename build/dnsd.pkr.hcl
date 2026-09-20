// Packer template for the dnsd appliance AMI.
//
//   Base      : Debian 13 (trixie) official cloud AMI
//   Artifact  : /opt/dashdns/dnsd, compiled in-guest from this working tree
//   Tuning    : /etc/sysctl.d/90-dnsd-network.conf + ethtool ring/queue sizing
//   Slimming  : redundant packages purged, unused kernel modules blacklisted
//               (and optionally deleted)
//
// Build both architectures:   packer build .
// Build one:                  packer build -only='amazon-ebs.amd64' .

packer {
  required_version = ">= 1.9.0"

  required_plugins {
    amazon = {
      version = ">= 1.3.0"
      source  = "github.com/hashicorp/amazon"
    }
  }
}

locals {
  // HH = 24-hour. Lowercase hh would be 12-hour and ambiguous.
  timestamp = formatdate("YYYYMMDD-HHmmss", timestamp())

  // Packaged working tree uploaded to the builder.
  //
  // Built by `make package` (or the tar command in README.md) *before* packer
  // runs: the file provisioner stats its source during Prepare, which happens
  // before any provisioner executes, so it cannot be produced by a
  // shell-local step inside this build block.
  src_tarball = "${path.root}/.artifacts/dnsd-src.tar.gz"

  common_tags = {
    Name          = "${var.ami_name_prefix}-${var.dnsd_version}"
    Application   = "dnsd"
    Version       = var.dnsd_version
    BaseOS        = "debian-13"
    BuiltBy       = "packer"
    BuildDate     = local.timestamp
    SourceAMIName = "{{ .SourceAMIName }}"
  }
}

// ---------------------------------------------------------------------------
// Sources
// ---------------------------------------------------------------------------

source "amazon-ebs" "amd64" {
  region        = var.region
  instance_type = var.instance_type_amd64

  ami_name        = "${var.ami_name_prefix}-amd64-${var.dnsd_version}-${local.timestamp}"
  ami_description = "dnsd eBPF/XDP DNS filtering appliance (Debian 13, amd64, ${var.dnsd_version})"
  ami_regions     = var.ami_regions
  ami_users       = var.ami_users
  ena_support     = true
  sriov_support   = true

  source_ami_filter {
    filters = {
      name                = var.source_ami_filter_amd64
      root-device-type    = "ebs"
      virtualization-type = "hvm"
      architecture        = "x86_64"
    }
    owners      = [var.debian_owner]
    most_recent = true
  }

  launch_block_device_mappings {
    device_name           = "/dev/xvda"
    volume_size           = var.volume_size
    volume_type           = var.volume_type
    delete_on_termination = true
    encrypted             = false
  }

  vpc_id                      = var.vpc_id
  subnet_id                   = var.subnet_id
  associate_public_ip_address = var.associate_public_ip_address
  ssh_interface               = var.ssh_interface
  iam_instance_profile        = var.iam_instance_profile

  ssh_username = var.ssh_username
  ssh_timeout  = "10m"

  // IMDSv2 on the build instance. This configures the builder, not the
  // resulting AMI — instances launched from it get their own settings.
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  tags          = merge(local.common_tags, { Architecture = "amd64" })
  snapshot_tags = merge(local.common_tags, { Architecture = "amd64" })
  run_tags      = { Name = "packer-dnsd-amd64-${local.timestamp}" }
}

source "amazon-ebs" "arm64" {
  region        = var.region
  instance_type = var.instance_type_arm64

  ami_name        = "${var.ami_name_prefix}-arm64-${var.dnsd_version}-${local.timestamp}"
  ami_description = "dnsd eBPF/XDP DNS filtering appliance (Debian 13, arm64, ${var.dnsd_version})"
  ami_regions     = var.ami_regions
  ami_users       = var.ami_users
  ena_support     = true

  source_ami_filter {
    filters = {
      name                = var.source_ami_filter_arm64
      root-device-type    = "ebs"
      virtualization-type = "hvm"
      architecture        = "arm64"
    }
    owners      = [var.debian_owner]
    most_recent = true
  }

  launch_block_device_mappings {
    device_name           = "/dev/xvda"
    volume_size           = var.volume_size
    volume_type           = var.volume_type
    delete_on_termination = true
    encrypted             = false
  }

  vpc_id                      = var.vpc_id
  subnet_id                   = var.subnet_id
  associate_public_ip_address = var.associate_public_ip_address
  ssh_interface               = var.ssh_interface
  iam_instance_profile        = var.iam_instance_profile

  ssh_username = var.ssh_username
  ssh_timeout  = "10m"

  // Configures the build instance, not the resulting AMI.
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  tags          = merge(local.common_tags, { Architecture = "arm64" })
  snapshot_tags = merge(local.common_tags, { Architecture = "arm64" })
  run_tags      = { Name = "packer-dnsd-arm64-${local.timestamp}" }
}

// ---------------------------------------------------------------------------
// Build
// ---------------------------------------------------------------------------

build {
  name = "dnsd"

  sources = [
    "source.amazon-ebs.amd64",
    "source.amazon-ebs.arm64",
  ]

  // cloud-init races apt; wait it out before touching dpkg.
  provisioner "shell" {
    script          = "${path.root}/scripts/00-wait-cloud-init.sh"
    execute_command = "chmod +x {{ .Path }}; sudo -S env {{ .Vars }} {{ .Path }}"
  }

  provisioner "file" {
    source      = local.src_tarball
    destination = "/tmp/dnsd-src.tar.gz"
  }

  # Created as the SSH user (not root) so the following upload can write into it.
  provisioner "shell" {
    inline = ["mkdir -p /tmp/dnsd-files"]
  }

  // Trailing slash on the source copies the *contents* of files/ into the
  // staging directory, preserving the etc/... and usr/... layout.
  provisioner "file" {
    source      = "${path.root}/files/"
    destination = "/tmp/dnsd-files"
  }

  provisioner "shell" {
    // `sudo -S env {{ .Vars }}` rather than `sudo -E sh -c '{{ .Vars }} ...'`:
    // Packer renders .Vars as single-quoted KEY='value' pairs, so wrapping it
    // in another layer of single quotes breaks the quoting.
    execute_command = "chmod +x {{ .Path }}; sudo -S env {{ .Vars }} {{ .Path }}"

    environment_vars = [
      "DEBIAN_FRONTEND=noninteractive",
      "GO_VERSION=${var.go_version}",
      "LLVM_VERSION=${var.llvm_version}",
      "DNSD_VERSION=${var.dnsd_version}",
      "DNSD_IFACE=${var.dnsd_iface}",
      "DNSD_UPSTREAM=${var.dnsd_upstream}",
      "DNSD_LINK_MODE=${var.dnsd_link_mode}",
      "DNSD_IPAM=${var.dnsd_ipam}",
      "SSH_USERNAME=${var.ssh_username}",
      "DEBUG_PASSWORD=${var.debug_password}",
      "STRIP_KERNEL_MODULES=${var.strip_kernel_modules}",
      "PURGE_PACKAGES=${var.purge_packages}",
      "DISABLE_UNATTENDED_UPGRADES=${var.disable_unattended_upgrades}",
    ]

    scripts = [
      "${path.root}/scripts/10-base-packages.sh",
      "${path.root}/scripts/20-build-dnsd.sh",
      "${path.root}/scripts/30-install-dnsd.sh",
      "${path.root}/scripts/40-sysctl-tuning.sh",
      "${path.root}/scripts/50-nic-tuning.sh",
      "${path.root}/scripts/60-purge-packages.sh",
      "${path.root}/scripts/70-kernel-modules.sh",
      "${path.root}/scripts/80-verify.sh",
      "${path.root}/scripts/99-cleanup.sh",
    ]
  }

  post-processor "manifest" {
    output     = "${path.root}/.artifacts/manifest.json"
    strip_path = true

    custom_data = {
      dnsd_version = var.dnsd_version
      base_os      = "debian-13"
      build_time   = local.timestamp
    }
  }
}
