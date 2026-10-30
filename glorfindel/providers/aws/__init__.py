"""The AWS adapter (MC1): written against a simulated world, never run on an AWS account.

See docs/design/monde-aws.md. The EC2 client is injected (client.Ec2Client); boto3 is
installed by litellm (DEP1), used only at MC2, and, like any AWS SDK, imported here only
(tests/unit/test_provider_boundary.py).
"""
