"""The AWS adapter (MC1): written against a simulated world, never run on an AWS account.

See docs/design/monde-aws.md. The EC2 client is injected (client.Ec2Client); boto3 comes
with MC2 and, like any AWS SDK, is imported here only (tests/unit/test_provider_boundary.py).
"""
