package GCP_terraform_gcp_security_compute_enable_shielded_vm

deny{
    not(gcp_security_compute_enable_shielded_vm)
}

# POLICY 9
# Verify shielded VM is enabled on compute instances
# Shielded VMs are virtual machines (VMs) on Google Cloud hardened by a set of security controls that help defend against rootkits and bootkits. Using Shielded VMs helps protect enterprise workloads from threats like remote attacks, privilege escalation, and malicious insiders. Shielded VMs leverage advanced platform security capabilities such as secure and measured boot, a virtual trusted platform module (vTPM), UEFI firmware, and integrity monitoring.
# Check if the `shielded_instance_config` is configured on the instance, and if `enable_vtpm` and `enable_integrity_monitoring` are set to `false`
gcp_security_compute_enable_shielded_vm {
shielded_instance_config
 }
 
shielded_instance_config[msg9]{
  shielded_config := input.resource.google_compute_instance[_].shielded_instance_config
  shielded_config != ""
  shielded_config.enable_vtpm == false
  shielded_config.enable_integrity_monitoring == false
  msg9 := "If the `shielded_instance_config` is configured on the instance then `enable_vtpm` and `enable_integrity_monitoring` must be set to `true`"
 }
 
shielded_instance_config[msg9]{
 shielded_config := input.resource.google_compute_instance[_]
 not shielded_config.shielded_instance_config
 msg9 := "`shielded_instance_config` must be configured on the instance"
}