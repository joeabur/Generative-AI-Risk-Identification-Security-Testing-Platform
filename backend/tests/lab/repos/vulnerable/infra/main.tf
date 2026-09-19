resource "aws_s3_bucket" "data" {
  bucket = "aegis-lab-vulnerable-fixture"
}

# Seeded: public-read ACL on a bucket.
resource "aws_s3_bucket_acl" "data" {
  bucket = aws_s3_bucket.data.id
  acl    = "public-read"
}

# Seeded: security group open to the world on SSH.
resource "aws_security_group" "open" {
  name = "aegis-lab-open"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
