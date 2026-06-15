from app.scanner.hcl_parser import parse_terraform
from app.scanner.cf_parser import parse_cloudformation

TF_CONTENT = """
resource "aws_s3_bucket" "my_bucket" {
  bucket = "test"
  acl    = "private"
}
"""

CF_CONTENT = """
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  MyBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: test-bucket
"""


def test_terraform_parser_returns_resources():
    resources = parse_terraform(TF_CONTENT)
    assert len(resources) == 1
    assert resources[0]["type"] == "aws_s3_bucket"
    assert resources[0]["name"] == "my_bucket"


def test_cloudformation_parser_returns_resources():
    resources = parse_cloudformation(CF_CONTENT)
    assert len(resources) == 1
    assert resources[0]["type"] == "AWS::S3::Bucket"
    assert resources[0]["name"] == "MyBucket"
