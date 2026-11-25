# DEPLOY.md: running Mini Gauntlet on AWS

A design note only; nothing here is deployed.

## Architecture

| Concern | Choice | Why |
|---|---|---|
| Compute | **ECS on Fargate**, two services (`api`, `web`) in private subnets, 2+ tasks each across 2 AZs | No servers to patch; scans run in the API task's worker threads, or later as separate Fargate tasks started by the API |
| Database | **RDS PostgreSQL** (Multi-AZ, encrypted with KMS, automated backups) | SQLite is right for one container but not for several tasks. Only `db.py` changes |
| Edge and networking | VPC with public subnets (ALB, NAT) and private subnets (tasks, RDS). **ALB** terminates TLS (ACM cert), **AWS WAF** in front. `web` is served via CloudFront + S3 or from the `web` service. Security groups: ALB → tasks → RDS only. VPC endpoints for ECR, S3, Secrets Manager and CloudWatch Logs | Nothing but the ALB is internet-facing |
| Secrets | **AWS Secrets Manager** for the DB password and the scan API key, injected as ECS task secrets. No secrets in images, env files or Git | Rotation and audit through CloudTrail |
| Logs and metrics | JSON logs to **CloudWatch Logs** (30-day retention), alarms on 5xx rate, failed scans and task restarts, ALB access logs to S3 | One place to debug a failed scan |
| Customer access | The scanner task role calls `sts:AssumeRole` into a **read-only role in each customer account**, protected by an ExternalId | The scanner never holds customer keys |

## CI/CD without long-lived keys

GitHub Actions uses **OIDC**: the workflow requests a short-lived token (`permissions: id-token: write`) and assumes an IAM role whose trust policy only accepts `repo:<org>/mini-gauntlet:ref:refs/heads/main`. That role can push to ECR and call `ecs:UpdateService` / `ecs:RegisterTaskDefinition` (plus `iam:PassRole` for the two task roles) and nothing else. Images are tagged with the commit SHA, then rolled out by ECS with deployment circuit breaker and automatic rollback. There are no `AWS_ACCESS_KEY_ID` secrets in GitHub.

## Least-privilege, read-only permissions for a live scanner

Attached to the role assumed in each customer account (resource `*`, because these are list/describe calls):

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "s3:ListAllMyBuckets",
      "s3:GetBucketLocation",
      "s3:GetBucketPublicAccessBlock",
      "s3:GetAccountPublicAccessBlock",
      "ec2:DescribeSecurityGroups",
      "iam:ListUsers",
      "iam:GetLoginProfile",
      "iam:ListMFADevices",
      "iam:ListAccessKeys",
      "rds:DescribeDBInstances"
    ],
    "Resource": "*"
  }]
}
```

| Check | Calls |
|---|---|
| AWS-S3-01 | `ListAllMyBuckets`, `GetBucketLocation`, `GetBucketPublicAccessBlock` (and `GetAccountPublicAccessBlock` for account-level settings) |
| AWS-EC2-01 | `ec2:DescribeSecurityGroups` (per region) |
| AWS-IAM-01 | `iam:ListUsers`, `iam:GetLoginProfile` (console access), `iam:ListMFADevices` |
| AWS-IAM-02 | `iam:ListAccessKeys` (status and creation date) |
| AWS-RDS-01 | `rds:DescribeDBInstances` (per region) |

None of these can read bucket contents, secrets or database data, or change anything. The trust policy allows only the scanner's task role and requires the ExternalId. The AWS-managed `SecurityAudit` policy would also work but grants far more than this catalog needs.

Azure and Google Cloud checks would use the built-in *Reader* (Azure) and *Security Reviewer* (GCP) roles, or custom roles limited to the same list/get calls.
