terraform {
  backend "s3" {
    bucket = "animalert-terraform-state-default"
    key    = "teraform.tfstate"  
    region = "eu-central-1"
  }
}
