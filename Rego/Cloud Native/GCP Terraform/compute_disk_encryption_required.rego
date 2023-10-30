package GCP_Terraform_gcp_security_compute_disk_encryption_required

deny{
    not(gcp_security_compute_disk_encryption_required)
}

# POLICY 8
# Disk encryption Keys should not be passed as plaintext
# Google Cloud compute instances should use disk encryption using a customer-supplied encryption key. One of the options is for the `disk_encryption_key` is `raw_key`, which is the key in plaintext. \n\nSensitive values such as raw encryption keys should not be included in your Terraform code and should be stored securely by a secrets manager

gcp_security_compute_disk_encryption_required[msg8]{
    disk := input.resource.google_compute_disk[_]
    not disk.disk_encryption_key
    msg8 := "disk_encryption_key block is missing"
} 

gcp_security_compute_disk_encryption_required[msg8]{ 
    disk := input.resource.google_compute_disk[_]
    disk_encryption_key := disk.disk_encryption_key
    disk_encryption_key != null
    disk.disk_encryption_key.raw_key
  msg8 := "raw_key should not be used"
}