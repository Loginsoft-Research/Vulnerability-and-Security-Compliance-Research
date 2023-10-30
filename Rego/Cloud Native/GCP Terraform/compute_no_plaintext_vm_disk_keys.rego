package GCP_terraform_gcp_security_compute_no_plaintext_vm_disk_keys

deny{
    not(gcp_security_compute_no_plaintext_vm_disk_keys)
}

# POLICY 13
# VM disk encryption keys should not be provided in plaintext
# Providing your encryption key in plaintext format means anyone with access to the source code also has access to the key.\n\nWhen encrypting a `boot_disk`, it is not recommended to use the `disk_encryption_key_raw` argument as this passes the key in plaintext, which is not secure. Consider using `kms_key_self_link` or a secrets manager instead.
gcp_security_compute_no_plaintext_vm_disk_keys[msg13]{
  disk_encryption =  input.resource.google_compute_instance[_]
  disk_encryption.disk_encryption_key_raw
  msg13 := "VM disk encryption keys should not be provided in plaintext"
 }