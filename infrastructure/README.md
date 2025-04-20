# DeepSeek LLM Service Infrastructure

This project contains the AWS CDK (Cloud Development Kit) infrastructure for deploying and managing the DeepSeek LLM Service. The infrastructure is designed to support an AI chatbot architecture with a React frontend, API Gateway WebSockets, and GPU-powered LLM inference services running in a secure VPC.

## Architecture Overview

The infrastructure consists of two main stacks:

1. **VPC Infrastructure Stack (`VpcInfrastructureStack`)**: Creates the foundational network architecture including VPC, subnets, NAT Gateway, security groups, and Application Load Balancer.
2. **LLM Service Infrastructure Stack (`LlmServiceInfraStack`)**: Provisions the GPU instances running the LLM service within the VPC created by the VPC Infrastructure Stack.

### Key Components

#### External Components (Outside VPC)
- **React Client Frontend**: The user-facing web application
- **API Gateway WebSockets**: Manages real-time communication with clients
- **Lambda Functions**: $authorizer and $connect handlers for WebSocket authentication and connection management
- **DynamoDB**: Stores WebSocket connection information

#### Internal Components (Inside VPC)
- **Private Application Load Balancer (ALB)**: Provides internal load balancing with HTTPS and sticky sessions for gRPC
- **Auto Scaling Group of GPU Instances**: Runs the LLM service containers
- **Lambda Message Handler**: Processes WebSocket messages and communicates with the LLM service
- **NAT Gateway**: Allows instances to access external services (DynamoDB, ECR, etc.)
- **VPC and Security Groups**: Network infrastructure and access controls

## VPC Infrastructure Stack

The VPC infrastructure stack creates the foundational network components:

### VPC Configuration
- **CIDR Block**: 172.16.0.0/16 (default)
- **Availability Zones**: Minimum of 2 AZs for high availability
- **Subnets**:
  - **Public Subnets**: For NAT Gateway placement
  - **Private Subnets**: For LLM service instances and Lambda functions

### Security Groups
1. **LLM Service Security Group**: Controls access to LLM service instances
   - Allows inbound traffic from the ALB security group on port 50051 (gRPC)
   - Allows inbound traffic from the ALB security group on port 443 (health checks)

2. **ALB Security Group**: Controls access to the private ALB
   - Allows inbound traffic from Lambda security group on port 443
   - Allows outbound traffic to LLM service security group on ports 50051 and 443

3. **Lambda Security Group**: Controls access for Lambda functions
   - Allows outbound traffic to ALB security group on port 443
   - Allows outbound traffic to internet via NAT Gateway for DynamoDB access

### Application Load Balancer (ALB)
- **Type**: Internal (private) Application Load Balancer
- **Listeners**: HTTPS (port 443)
- **Custom Domain**: deepseek.jonathanmau.com
- **TLS Certificate**: ACM certificate (ARN: arn:aws:acm:us-west-2:034362047054:certificate/436d84a6-1cc3-432c-b5ca-d9150749a5f6)
- **Target Group Configuration**:
  - Protocol: HTTPS with HTTP/2 support for gRPC
  - Port: 50051
  - Health Check: Path: `/health`, Port: 443, Protocol: HTTPS
  - Sticky Sessions: Enabled with cookie "LlmServiceStickiness"
  - Deregistration Delay: 120 seconds to allow gRPC streams to complete

### NAT Gateway
- Deployed in public subnet for cost optimization
- Allows outbound internet access for instances in private subnets

### Gateway Endpoints
- **S3 Endpoint**: Allows instances to access S3 without going through NAT Gateway

### SSM Parameters
- Stores all infrastructure values like VPC ID, subnet IDs, security group IDs, etc. for cross-stack references

## LLM Service Infrastructure Stack

The LLM Service Infrastructure Stack deploys the GPU instances that run the LLM service:

### Auto Scaling Group
- **Instance Type**: c5.2xlarge (can be adjusted based on inference needs)
- **AMI**: Latest Amazon Linux 2
- **Spot Instances**: Used for cost optimization with a max price of $0.25
- **Min/Max Capacity**: 1/1 (can be adjusted for scaling)
- **EBS Storage**: 30GB encrypted GP3 volume
- **AZ Distribution**: Deployed across multiple AZs for high availability

### Security
- **IAM Role**: Instance role with permissions for:
  - ECR image pulling
  - CloudWatch Logs creation and management
  - SSM Session Manager for secure instance access

### Health Checks
- **HTTPS Health Check Proxy**: Custom Python service that:
  - Runs on port 443 with self-signed TLS certificate
  - Bridges ALB HTTPS health checks to the container's gRPC health check
  - Supports sticky sessions with cookie management
  - Ensures instances are deregistered from the ALB when unhealthy

### Service Container
- **Container Image**: Pulled from private ECR repository
- **Environment Variables**:
  - MODEL_NAME: Specifies which LLM model to load
  - gRPC HTTP/2 settings for optimal ALB compatibility
  - Sticky session configuration

### Auto Scaling Policies
- **CPU Scaling**: Target tracking policy (70% target utilization)
- **Scheduled Scaling**: Scales down during off-hours to save costs
  - Down at 12am Central Time (6am UTC)
  - Up at 9am Central Time (3pm UTC)

## Deployment Process

### Deployment Order
1. Deploy the VPC Infrastructure Stack first:
   ```bash
   npx cdk deploy VpcInfrastructureStack
   ```

2. Then deploy the LLM Service Infrastructure Stack:
   ```bash
   npx cdk deploy LlmServiceInfraStack
   ```

### Prerequisites
- ACM certificate for your custom domain
- Environment variables in a `.env` file:
  ```
  DEEPSEEK_ACM_ARN=arn:aws:acm:us-west-2:034362047054:certificate/436d84a6-1cc3-432c-b5ca-d9150749a5f6
  ```

## Service Communication Flow

1. **Client** → **API Gateway WebSockets** → **DynamoDB** (connection storage)
2. **Client** sends message → **$message Lambda Handler** (in VPC) → **Private ALB** → **LLM Service** (on GPU instance)
3. **LLM Service** generates response → **$message Lambda Handler** → **API Gateway WebSockets** → **Client**

## Sticky Sessions Implementation

The architecture implements sticky sessions to ensure that conversation state is maintained between a client and a specific LLM service instance:

1. **ALB Target Group Configuration**:
   - `stickiness.enabled` = "true"
   - `stickiness.type` = "app_cookie"  
   - `stickiness.app_cookie.cookie_name` = "LlmServiceStickiness"
   - `stickiness.app_cookie.duration_seconds` = "900" (15 minutes)

2. **Health Check Proxy**:
   - HTTPS-based health check proxy creates and sets sticky session cookies
   - Implements secure cookie handling with HttpOnly and Secure flags
   - Generates unique session IDs using UUID format

3. **LLM Service**:
   - Detects existing cookies in gRPC metadata
   - Creates and returns new cookies for new sessions
   - Sets trailing metadata with Set-Cookie header
   - Ensures proper cookie lifetime and security attributes

## TLS/HTTPS Configuration

The architecture implements end-to-end HTTPS security:

1. **Custom Domain**: deepseek.jonathanmau.com with ACM certificate
2. **ALB Listener**: Uses imported ACM certificate for TLS termination
3. **Health Check Proxy**: HTTPS with self-signed certificate
4. **gRPC Service**: Configurable TLS support for secure communication

## Monitoring and Logging

- **CloudWatch Log Groups**: Captures logs from:
  - System logs
  - Docker container logs
  - LLM service application logs
  - Health check proxy logs
- **CloudWatch Metrics**: Auto Scaling metrics for capacity planning
- **CloudWatch Alarms**: Can be configured for operational monitoring (not implemented)

## Customization and Configuration

You can customize the deployment by modifying:

- **EC2 instance type** in `llm-service-infra-stack.ts` (currently c5.2xlarge)
- **Spot instance pricing** (currently max $0.25)
- **Auto scaling parameters** (min/max capacity, scaling policies)
- **Model name** environment variable (currently "deepseek-r1:1.5b")
- **ALB and health check settings** (timeouts, intervals, paths)

## Security Considerations

The architecture implements security best practices:

1. **Network Isolation**:
   - Private subnets for LLM service instances
   - Security groups with least privilege
   - Internal ALB not exposed to the internet

2. **Authentication and Authorization**:
   - API Gateway authorizers for WebSocket connections
   - IAM roles with minimal permissions

3. **Data Protection**:
   - TLS encryption for all traffic
   - Encrypted EBS volumes
   - HTTPS health checks

## Useful Commands

* `npm run build`   - Compile TypeScript to JavaScript
* `npm run watch`   - Watch for changes and compile
* `npm run test`    - Perform Jest unit tests
* `npx cdk deploy`  - Deploy stack to AWS
* `npx cdk diff`    - Compare deployed stack with current state
* `npx cdk synth`   - Emit CloudFormation template

## Troubleshooting

### Common Issues

1. **Instance Health Check Failures**:
   - Check HTTPS health check proxy logs
   - Verify security group allows traffic on port 443
   - Check that the LLM service is running correctly

2. **Sticky Session Issues**:
   - Verify ALB target group has stickiness enabled
   - Check that the LLM service is setting cookies correctly
   - Look for Set-Cookie headers in gRPC responses

3. **gRPC Communication Problems**:
   - Verify HTTP/2 settings in ALB and LLM service configuration
   - Check connection timeouts for long-running inference
   - Verify security group rules allow gRPC traffic

4. **NAT Gateway Connectivity**:
   - Check route tables for private subnets
   - Verify elastic IP assignment to NAT Gateway
   - Ensure outbound traffic is permitted by security groups

## Future Improvements

Potential enhancements to consider:

1. **Multi-region deployment** for global high availability
2. **Auto scaling based on queue depth** rather than just CPU
3. **Reserved instances** for cost optimization on baseline capacity
4. **Enhanced monitoring** with custom CloudWatch dashboards
5. **GPU acceleration** with optimized instance types (g4dn, g5 series)
6. **Blue/green deployments** for zero-downtime updates
7. **AWS PrivateLink** for secure API Gateway integration
