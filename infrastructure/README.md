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
- **Creation**: The ECR repository is referenced in the pipeline stack (not created) and should already exist before the pipeline stack deployment

### How the ECR Process Works

1. **Image Building**:
   - The CI/CD pipeline automatically builds a Docker image when changes are pushed to the GitHub repository
   - The build process uses a CodeBuild project with Docker capabilities
   - **Important**: The Dockerfile is located in the `service/` directory of the repository, but the CodeBuild project looks for it at the repository root
   - The command executed is: `docker build -t $ECR_REPOSITORY_URI:$IMAGE_TAG .` from the repository root
   - **Note**: If builds are failing, ensure one of the following:
     - Move the Dockerfile to the repository root, OR
     - Modify the CodeBuild buildspec to change directory to service/ before building, OR
     - Update the build command to specify the Dockerfile path: `docker build -t $ECR_REPOSITORY_URI:$IMAGE_TAG -f service/Dockerfile .`
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


1. Add a GitHub Personal Access Token to AWS Secrets Manager with the name `deepseek-llm-service-pat` and key `github-token`

2. Deploy the CI/CD pipeline stack:
   ```bash
   npm run build
   npx cdk deploy LlmServiceCicdPipelineStack
   ```

### Automated CI/CD Flow

1. Changes pushed to the GitHub repository trigger the pipeline
2. The pipeline pulls the source code
3. CodeBuild builds the Docker image:
   - Pre-build: Authenticates with ECR and prepares image tags
   - Build: Attempts to build the Docker image with the commit hash tag and 'latest' tag
   - **Issue Alert**: By default, CodeBuild looks for the Dockerfile in the root directory, but it's actually in the service/ directory
   - Post-build (if successful): Pushes both tagged images to ECR
4. The infrastructure stack is deployed or updated
5. EC2 instances pull the latest image and run the service


## Fixing the Docker Build Issue

To resolve the issue with CodeBuild not finding the Dockerfile, you have three options:

1. **Update the BuildSpec**: Modify the CI/CD pipeline stack to change the build command:
   ```typescript
   // In cicd-pipeline-stack.ts, modify the build commands section:
   build: {
     commands: [
       "echo Build started on `date`",
       "echo Building the Docker image...",
       // Specify the Dockerfile location
       "docker build -t $ECR_REPOSITORY_URI:$IMAGE_TAG -f service/Dockerfile .",
       // Alternative approach
       // "cd service && docker build -t $ECR_REPOSITORY_URI:$IMAGE_TAG .",
       "docker tag $ECR_REPOSITORY_URI:$IMAGE_TAG $ECR_REPOSITORY_URI:latest",
     ],
   },
   ```

2. **Copy/Move Dockerfile**: Create a Dockerfile in the root that references the service Dockerfile:
   ```dockerfile
   # Root Dockerfile
   FROM service/Dockerfile
   ```

3. **Repository Restructuring**: Move the Dockerfile to the repository root (least recommended)

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
   - Check if the Dockerfile path is correct in the build command
   - Verify that all files referenced in the Dockerfile exist
   - Check CodeBuild logs for specific error messages
   - Ensure the ECR repository exists before running the pipeline

## Future Improvements

Consider implementing:

1. ECR lifecycle policies to manage old images
2. More restrictive IAM permissions for deployment
3. Enhanced monitoring and alerting
4. Cost optimization for EC2 instances
5. Multi-region deployment for high availability
