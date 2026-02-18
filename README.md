# awsclaw

One-command deploy for OpenClaw on AWS EC2 with SSH access.

## Interactive deploy

```bash
./deploy_openclaw_ec2.sh
```

Prompts:
- Bot name (used as EC2 `Name` tag)
- Network mode:
  - `ipv4` (public IPv4 SSH)
  - `dualstack` (public IPv4 + IPv6)
  - `ipv6-only` (public IPv6 only, no public IPv4 hourly charge)

## Non-interactive deploy

```bash
./deploy_openclaw_ec2.sh --yes --bot-name my-bot --network-mode ipv4
```

## Optional flags

```bash
./deploy_openclaw_ec2.sh \
  --yes \
  --bot-name my-bot \
  --network-mode dualstack \
  --instance-type t3.small \
  --region us-east-1
```

## What the script does

- Creates/reuses IAM role + instance profile for EC2 (`openclaw-ec2-role`, `openclaw-ec2-profile`)
- Creates/reuses a security group and applies SSH ingress rules based on selected network mode
- For IPv6 modes, ensures VPC/subnet IPv6 routing is configured in default VPC
- Creates a fresh EC2 key pair in `~/.ssh/`
- Launches Amazon Linux 2023 and installs OpenClaw non-interactively via:
  - `curl -fsSL https://openclaw.ai/install.sh | bash`
- Waits for instance checks and prints SSH command(s)
