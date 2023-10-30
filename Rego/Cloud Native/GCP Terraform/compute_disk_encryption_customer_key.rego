package GCP_Terraform_gcp_security_compute_disk_encryption_customer_key

deny{
    not(gcp_security_compute_disk_encryption_customer_key)
}

# POLICY 7
# Disks should be encrypted with Customer Supplied Encryption Keys
# Google Cloud compute instances should use disk encryption using a customer-supplied encryption key. If you do not provide an encryption key when creating the disk, then the disk will be encrypted using an automatically generated key, and you do not need to provide the key to use the disk later.

gcp_security_compute_disk_encryption_customer_key[msg7]{
    disk := input.resource.google_compute_disk[_]
    not disk.disk_encryption_key
    msg7 := "disk_encryption_key block is missing"
} 

gcp_security_compute_disk_encryption_customer_key[msg7]{ 
    disk := input.resource.google_compute_disk[_]
    disk_encryption_key := disk.disk_encryption_key
    disk_encryption_key != null
    disk_encryption_key.kms_key_self_link == ""
    msg7 := "The `disk_encryption_key` key is defined and the arguments must not be empty strings."
}
