package GCP_Terraform_gcp_security_compute_no_ip_forwarding

deny{
    not(gcp_security_compute_no_ip_forwarding)
}

# POLICY 12
# Compute instances should be configured with IP forwarding
# Disabling IP forwarding ensures the instance can only receive packets addressed to the instance and can only send packets with a source address of the instance.\n\nThe attribute `can_ip_forward` is optional on `google_compute_instance` and defaults to `false`. Instances with `can_ip_forward = true` will fail. \n
gcp_security_compute_no_ip_forwarding[msg12]{
  input.resource.google_compute_instance[_].can_ip_forward != false 
  msg12 := "Compute instances should be configured with IP forwarding"
 }