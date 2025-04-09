# DeepSeek LLM Service Infrastructure

This project contains the AWS CDK (Cloud Development Kit) infrastructure for deploying and managing the DeepSeek LLM Service. The infrastructure is designed to be fully automated through a CI/CD pipeline and leverages several AWS services including ECR, EC2 Auto Scaling Groups, CodePipeline, and Cloud Map for service discovery.

## Architecture Overview

The infrastructure consists of two main stacks:

1. **CI/CD Pipeline Stack (`LlmServiceCicdPipelineStack`)**: Manages the continuous integration and deployment process.
2. **LLM Service Infrastructure Stack (`LlmServiceInfraStack`)**: Provisions the actual runtime infrastructure for the service.

### Key Components

- **Amazon ECR Repository**: Stores Docker images for the LLM service
- **CodePipeline**: Orchestrates the CI/CD workflow
- **CodeBuild**: Builds and pushes Docker images
- **EC2 Auto Scaling Group**: Runs the LLM service containers
- **Cloud Map**: Provides service discovery for the distributed components
- **VPC and Security Groups**: Network infrastructure

## ECR (Elastic Container Registry) Details

The ECR repository is a critical component of the infrastructure:

- **Repository Name**: `llm-service`
- **Repository URI Format**: `${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/llm-service`

### How the ECR Process Works

1. **Image Building**:
   - The CI/CD pipeline automatically builds a Docker image when changes are pushed to the GitHub repository
   - The build process uses a CodeBuild project with Docker capabilities
   - The Dockerfile is located in the `service/` directory of the repository
   - CodeBuild executes the build from the repository root using: `docker build -t $ECR_REPOSITORY_URI:$IMAGE_TAG .`
   - The build uses a multi-stage process defined in `service/Dockerfile`:
     - First stage installs dependencies and generates Protocol Buffer code
     - Second stage creates the final lightweight image with only necessary components
   - Each image is tagged with both the Git commit hash (short form) and `latest`

2. **Image Storage**:
   - Images are pushed to the ECR repository with unique tags
   - The repository maintains version history through these tags
   - The `latest` tag always points to the most recently built image

3. **Image Deployment**:
   - EC2 instances in the Auto Scaling Group pull the image from ECR
   - The instances authenticate with ECR using instance roles
   - The Docker image is pulled using the command:
     ```
     aws ecr get-login-password --region ${AWS_REGION} | docker login --username AWS --password-stdin ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com
     docker pull ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/llm-service:latest
     ```
   - The container is run with the necessary environment variables, particularly the LLM model name

4. **Image Lifecycle**:
   - Old images are retained in ECR for rollback capability
   - You may want to set up lifecycle policies to automatically clean up old images

## Deployment Process

### Initial Setup

1. Create the ECR repository manually (required before first deployment):
   ```bash
   aws ecr create-repository --repository-name llm-service
   ```

2. Add a GitHub Personal Access Token to AWS Secrets Manager with the name `deepseek-llm-service-pat` and key `github-token`

3. Deploy the CI/CD pipeline stack:
   ```bash
   npx cdk deploy LlmServiceCicdPipelineStack
   ```

### Automated CI/CD Flow

1. Changes pushed to the GitHub repository trigger the pipeline
2. The pipeline pulls the source code
3. CodeBuild builds the Docker image using the Dockerfile in the service/ directory
   - Pre-build: Authenticates with ECR and prepares image tags
   - Build: Builds the Docker image with the commit hash tag and 'latest' tag
   - Post-build: Pushes both tagged images to ECR
4. The infrastructure stack is deployed or updated
5. EC2 instances pull the latest image and run the service

### Manual Deployment Options

For testing or initial deployment without using the pipeline:

```bash
# Set environment variable to enable manual deployment
export MANUAL_DEPLOY=true

# Deploy the infrastructure stack directly
npx cdk deploy LlmServiceInfraStack
```

## Service Docker Image

The service is containerized using a multi-stage Dockerfile located in the `service/` directory:

1. **Build Stage**:
   - Uses python:3.10-slim as the base image
   - Installs Poetry for dependency management
   - Installs all production dependencies
   - Generates Protocol Buffer code
   - Copies service source code

2. **Final Stage**:
   - Uses a clean python:3.10-slim image
   - Copies only necessary files from the build stage
   - Sets up environment variables with sensible defaults
   - Includes a health check using grpcurl
   - Exposes port 50051 for gRPC traffic
   - Runs the LLM service with the `python -m llm_service.main` command

This multi-stage approach ensures the final image is as small as possible while containing all necessary components to run the service.

## Infrastructure Components in Detail

### LLM Service Infrastructure

- **VPC**: Provides network isolation with public and private subnets
- **Auto Scaling Group**: Launches EC2 instances with the following configuration:
  - Uses T3.micro instances (can be adjusted for production)
  - Runs as spot instances to reduce costs
  - Scales based on CPU utilization (70% threshold)
  - Uses latest Amazon Linux 2 AMI
  - User data script pulls and runs the Docker container
- **Service Discovery**: Uses AWS Cloud Map to register service instances
  - Private DNS namespace: `llm-service`
  - A-record DNS entries for each instance
  - Health checks via TCP

### CI/CD Pipeline

- **Source Stage**: Pulls code from GitHub repository
- **Build Stage**: Builds Docker image and pushes to ECR
- **Deploy Stage**: Deploys or updates the infrastructure stack

## Customization and Configuration

You can customize the deployment by modifying:

- EC2 instance type in `llm-service-infra-stack.ts`
- Auto scaling parameters (min/max/desired capacity)
- GitHub repository details in `cicd-pipeline-stack.ts`
- Model name environment variable in the container launch command

## Useful Commands

* `npm run build`   - Compile TypeScript to JavaScript
* `npm run watch`   - Watch for changes and compile
* `npm run test`    - Perform Jest unit tests
* `npx cdk deploy`  - Deploy stack to AWS
* `npx cdk diff`    - Compare deployed stack with current state
* `npx cdk synth`   - Emit CloudFormation template

## Troubleshooting

### Common Issues

1. **ECR Authentication Failures**:
   - Check IAM roles and policies for EC2 instances
   - Verify that the ECR repository exists
   - Ensure the region is correctly specified

2. **Instance Startup Issues**:
   - Check CloudWatch Logs for user data script output
   - Verify security group allows necessary traffic
   - Ensure instance has internet access for pulling images

3. **Image Build Failures**:
   - Review CodeBuild logs for specific errors
   - Check Docker build context and Dockerfile syntax
   - Verify the Dockerfile in the service/ directory is valid

## Future Improvements

Consider implementing:

1. ECR lifecycle policies to manage old images
2. More restrictive IAM permissions for deployment
3. Enhanced monitoring and alerting
4. Cost optimization for EC2 instances
5. Multi-region deployment for high availability
