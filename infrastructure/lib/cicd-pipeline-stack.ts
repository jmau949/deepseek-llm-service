import * as cdk from "aws-cdk-lib";
import * as codebuild from "aws-cdk-lib/aws-codebuild";
import * as codepipeline from "aws-cdk-lib/aws-codepipeline";
import * as codepipeline_actions from "aws-cdk-lib/aws-codepipeline-actions";
import * as ecr from "aws-cdk-lib/aws-ecr";
import * as iam from "aws-cdk-lib/aws-iam";
import * as aws_secretsmanager from "aws-cdk-lib/aws-secretsmanager";
import { Construct } from "constructs";

export class CicdPipelineStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // First create a secret with the correct naming convention for ECR pull-through cache
    // Import the existing Docker Hub credentials secret
    const existingDockerHubSecret = aws_secretsmanager.Secret.fromSecretNameV2(
      this,
      "ExistingDockerHubSecret",
      "docker-hub-credentials" // Use the secret name, not the ARN
    );

    // Create a new secret with the required naming convention for ECR pull-through cache
    const dockerHubEcrSecret = new aws_secretsmanager.CfnSecret(
      this,
      "DockerHubEcrSecret",
      {
        name: "ecr-pullthroughcache/dockerhub",
        description: "Docker Hub credentials for ECR pull-through cache",
        secretString: JSON.stringify({
          username:
            "{{resolve:secretsmanager:docker-hub-credentials:SecretString:username}}",
          accessToken:
            "{{resolve:secretsmanager:docker-hub-credentials:SecretString:password}}",
        }),
      }
    );

    // Create ECR pull-through cache for Docker Hub to avoid rate limiting
    const dockerHubCache = new ecr.CfnPullThroughCacheRule(
      this,
      "DockerHubCache",
      {
        ecrRepositoryPrefix: "docker-hub",
        upstreamRegistryUrl: "registry-1.docker.io",
        credentialArn: dockerHubEcrSecret.ref,
      }
    );
    console.log("dockerHubCache", dockerHubCache);

    // Use existing ECR repository
    const ecrRepository = ecr.Repository.fromRepositoryName(
      this,
      "LlmServiceEcrRepository",
      "llm-service"
    );

    // Define the artifact for source code
    const sourceOutput = new codepipeline.Artifact("SourceCode");

    // Define the artifact for built container image
    const buildOutput = new codepipeline.Artifact("BuildOutput");

    // Create a CodeBuild project for building Docker images
    const buildProject = new codebuild.PipelineProject(
      this,
      "LlmServiceBuild",
      {
        environment: {
          buildImage: codebuild.LinuxBuildImage.STANDARD_7_0,
          privileged: true, // Required for Docker builds
        },
        environmentVariables: {
          ECR_REPOSITORY_URI: {
            value: ecrRepository.repositoryUri,
          },
          AWS_ACCOUNT_ID: {
            value: this.account,
          },
          AWS_REGION: {
            value: this.region,
          },
        },
        buildSpec: codebuild.BuildSpec.fromObject({
          version: "0.2",
          phases: {
            pre_build: {
              commands: [
                "echo Logging in to Amazon ECR...",
                "aws ecr get-login-password --region $AWS_REGION | docker login --username AWS --password-stdin $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com",
                "# Make sure the ECR credentials are properly configured",
                "# Ensure we have proper AWS credentials by checking the caller identity",
                "aws sts get-caller-identity",
                "# Check if the ECR repository exists",
                "echo 'Checking ECR repository...'",
                "aws ecr describe-repositories --repository-names llm-service || (echo 'ERROR: ECR repository llm-service does not exist or cannot be accessed' && exit 1)",
                "# Verify ECR push/pull permissions",
                "echo 'Checking ECR repository policy...'",
                "aws ecr get-repository-policy --repository-name llm-service 2>&1 | grep -q 'RepositoryPolicyNotFoundException' && echo 'Repository exists but has no policy set (using default permissions)' || aws ecr get-repository-policy --repository-name llm-service || (echo 'ERROR: Cannot access repository or other policy error' && exit 1)",
                "# Refresh ECR login to ensure it's valid",
                "echo 'Refreshing ECR login...'",
                "aws ecr get-login-password --region $AWS_REGION | docker login --username AWS --password-stdin $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com",
                "# Make sure the ECR pull-through cache is properly configured",
                "echo 'Configuring Docker to use ECR pull-through cache...'",
                "mkdir -p $HOME/.docker",
                "# Create Docker config with ECR credentials helper",
                'echo \'{"credHelpers":{"$AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com":"ecr-login"}}\' > $HOME/.docker/config.json',
                "# Add registry mirrors config for Docker daemon",
                'echo \'{"registry-mirrors": ["https://$AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com"]}\' | sudo tee /etc/docker/daemon.json',
                "# Restart Docker daemon to apply changes",
                "sudo systemctl restart docker || sudo service docker restart || (echo 'Failed to restart Docker via systemd or service, trying direct daemon restart' && sudo dockerd &)",
                "# Wait for Docker daemon to be ready",
                "sleep 5",
                "# Verify Docker is properly configured",
                "docker info",
                "# Create .aws/config to ensure pulling from ECR cache works",
                "mkdir -p $HOME/.aws",
                "echo '[default]' > $HOME/.aws/config",
                "echo 'region = $AWS_REGION' >> $HOME/.aws/config",
                "# Verify the pull-through cache rules are configured correctly",
                "echo 'Checking pull-through cache rules...'",
                "aws ecr describe-pull-through-cache-rules --query 'pullThroughCacheRules[?ecrRepositoryPrefix==`docker-hub`]' --output text 2>/dev/null | grep -q 'docker-hub' || { echo 'ERROR: Pull-through cache rule for docker-hub not found or cannot be verified.'; echo 'The CDK stack must properly configure dockerHubCache.'; exit 1; }",
                "# Verify ECR auth token works",
                "aws ecr get-login-password --region $AWS_REGION | docker login --username AWS --password-stdin $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com",
                "# Install jq for JSON processing",
                "sudo apt-get update && sudo apt-get install -y jq",
                "# Set up version tagging based on Git information",
                "echo Setting up version tagging...",
                "COMMIT_HASH=$(echo $CODEBUILD_RESOLVED_SOURCE_VERSION | cut -c 1-7)",
                "BRANCH_NAME=$(echo $CODEBUILD_WEBHOOK_HEAD_REF | sed 's/refs\\/heads\\///')",
                "BRANCH_NAME=${BRANCH_NAME:-master}", // Default to master if branch name is empty
                "echo Branch name: $BRANCH_NAME",
                "echo Commit hash: $COMMIT_HASH",
                "# Create semantic version-like tag",
                "BUILD_DATE=$(date +%Y%m%d%H%M)",
                'IMAGE_TAG="0.1.0-$([ "$BRANCH_NAME" = "master" ] || [ "$BRANCH_NAME" = "main" ] && echo "$COMMIT_HASH" || echo "$BRANCH_NAME-$COMMIT_HASH")"',
                'LATEST_TAG="latest"',
                "echo Image will be tagged as: $IMAGE_TAG and $LATEST_TAG",
                "echo Repository structure for debugging:",
                "find . -type f -name 'Dockerfile' | sort",
                "ls -la",
              ],
            },
            build: {
              commands: [
                "echo Build started on `date`",
                "echo Building the Docker image...",
                "echo Current directory: $(pwd)",
                "echo Repository root contents:",
                "ls -la",
                "# Verify Docker login is working",
                "docker info",
                "# Re-authenticate with ECR",
                "aws ecr get-login-password --region $AWS_REGION | docker login --username AWS --password-stdin $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com",
                "# Define function to modify Dockerfile to use ECR cache",
                'modify_dockerfile() { if [ -f "$1" ]; then echo "Modifying Dockerfile at $1 to use ECR cache..."; sed -i.bak "s|FROM python:|FROM $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/docker-hub/python:|g" "$1"; sed -i.bak "s|FROM node:|FROM $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/docker-hub/node:|g" "$1"; sed -i.bak "s|FROM ubuntu:|FROM $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/docker-hub/ubuntu:|g" "$1"; sed -i.bak "s|FROM busybox:|FROM $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/docker-hub/busybox:|g" "$1"; echo "Modified Dockerfile:"; cat "$1"; fi; }',
                // Replace the multi-line if statement with a single command:
                'bash -c \'if [ -f ./service/Dockerfile ]; then echo "Dockerfile found in service directory"; cd service; echo "Changed to service directory: $(pwd)"; ls -la; modify_dockerfile Dockerfile; echo "Building Docker image with --no-cache option to avoid rate limit issues..."; docker build --no-cache -t $ECR_REPOSITORY_URI:$IMAGE_TAG .; docker tag $ECR_REPOSITORY_URI:$IMAGE_TAG $ECR_REPOSITORY_URI:$LATEST_TAG; elif [ -f Dockerfile ]; then echo "Dockerfile found in root directory"; modify_dockerfile Dockerfile; echo "Building Docker image with --no-cache option to avoid rate limit issues..."; docker build --no-cache -t $ECR_REPOSITORY_URI:$IMAGE_TAG .; docker tag $ECR_REPOSITORY_URI:$IMAGE_TAG $ECR_REPOSITORY_URI:$LATEST_TAG; else echo "ERROR: Dockerfile not found in expected locations!"; find . -name "Dockerfile" -type f; exit 1; fi\'',
              ],
            },
            post_build: {
              commands: [
                "echo Build completed on `date`",
                'bash -c \'if [ $CODEBUILD_BUILD_SUCCEEDING = 1 ]; then echo "Pushing the Docker image..."; echo "Docker images available:"; docker images; echo "DEBUG: Repository URI is $ECR_REPOSITORY_URI"; echo "DEBUG: Image tag is $IMAGE_TAG"; echo "DEBUG: Latest tag is $LATEST_TAG"; echo "Refreshing ECR login credentials..."; aws ecr get-login-password --region $AWS_REGION | docker login --username AWS --password-stdin $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com || { echo "ERROR: ECR login failed"; exit 1; }; echo "Verifying AWS identity and permissions:"; aws sts get-caller-identity || { echo "ERROR: Could not get caller identity"; exit 1; }; echo "Verifying ECR repository exists:"; aws ecr describe-repositories --repository-names llm-service || { echo "ERROR: Cannot access ECR repository"; exit 1; }; echo "Executing docker push $ECR_REPOSITORY_URI:$IMAGE_TAG"; docker push $ECR_REPOSITORY_URI:$IMAGE_TAG || { echo "ERROR: Failed to push $ECR_REPOSITORY_URI:$IMAGE_TAG"; exit 1; }; echo "Executing docker push $ECR_REPOSITORY_URI:$LATEST_TAG"; docker push $ECR_REPOSITORY_URI:$LATEST_TAG || { echo "ERROR: Failed to push $ECR_REPOSITORY_URI:$LATEST_TAG"; exit 1; }; echo "Successfully pushed Docker image with tags: $IMAGE_TAG and $LATEST_TAG"; echo "Writing image definition file..."; cd $CODEBUILD_SRC_DIR; echo "{\\"ImageURI\\":\\"$ECR_REPOSITORY_URI:$IMAGE_TAG\\"}" > imageDefinition.json; echo "Image definition file created:"; cat imageDefinition.json; if [ "$BRANCH_NAME" = "master" ] || [ "$BRANCH_NAME" = "main" ]; then echo "Creating GitHub release for commit $COMMIT_HASH"; echo "GitHub release creation will be implemented in a future update"; fi; else echo "Build failed, skipping Docker push"; exit 1; fi\'',
              ],
            },
          },
          artifacts: {
            files: ["imageDefinition.json"],
            "base-directory": "$CODEBUILD_SRC_DIR",
            "discard-paths": "no",
          },
        }),
      }
    );

    // Grant permissions to the CodeBuild project to push to ECR
    ecrRepository.grantPullPush(buildProject);

    // Add explicit ECR permissions to ensure authentication works
    buildProject.addToRolePolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: [
          "ecr:GetAuthorizationToken",
          "ecr:BatchCheckLayerAvailability",
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage",
          "ecr:InitiateLayerUpload",
          "ecr:UploadLayerPart",
          "ecr:CompleteLayerUpload",
          "ecr:PutImage",
          "ecr:DescribeRepositories",
          "ecr:GetRepositoryPolicy",
          "ecr:DescribePullThroughCacheRules",
          "ecr:ListImages",
        ],
        resources: ["*"],
      })
    );

    console.log("dummy rebuild");

    // Grant permissions to access the GitHub token in Secrets Manager
    buildProject.addToRolePolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: ["secretsmanager:GetSecretValue"],
        resources: [
          `arn:aws:secretsmanager:${this.region}:${this.account}:secret:deepseek-llm-service-pat*`,
        ],
      })
    );

    // Create a CodeBuild project for deploying infrastructure
    const deployProject = new codebuild.PipelineProject(
      this,
      "LlmServiceDeploy",
      {
        environment: {
          buildImage: codebuild.LinuxBuildImage.STANDARD_7_0,
          privileged: true,
        },
        environmentVariables: {
          IMAGE_URI: {
            value: buildOutput.artifactName,
            type: codebuild.BuildEnvironmentVariableType.PLAINTEXT,
          },
          ECR_REPOSITORY_URI: {
            value: ecrRepository.repositoryUri,
            type: codebuild.BuildEnvironmentVariableType.PLAINTEXT,
          },
        },
        buildSpec: codebuild.BuildSpec.fromObject({
          version: "0.2",
          phases: {
            install: {
              commands: [
                "which n || npm install -g n",
                "n 18",
                "node --version",
                "npm install -g aws-cdk",
                "echo 'Checking repository structure...'",
                "ls -la",
                "find . -type d -name 'infrastructure' | sort",
              ],
            },
            build: {
              commands: [
                "echo Deploying infrastructure...",
                "# First find where infrastructure directory is",
                "INFRA_DIR=$(find . -type d -name 'infrastructure' | head -1)",
                "if [ -z \"$INFRA_DIR\" ]; then echo 'Cannot find infrastructure directory' && exit 1; fi",
                'echo "Found infrastructure directory at: $INFRA_DIR"',
                'cd "$INFRA_DIR"',
                "npm install",
                "npx cdk deploy LlmServiceInfraStack --require-approval never",
              ],
            },
          },
        }),
      }
    );

    // Grant permissions to the deploy project
    const deployRole = deployProject.role!;
    // Remove the administrator access policy
    // deployProject.role?.addManagedPolicy(
    //   iam.ManagedPolicy.fromAwsManagedPolicyName("AdministratorAccess")
    // );

    // Add specific permissions required for deployment
    deployRole.addToPrincipalPolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: [
          // Allow CDK to deploy CloudFormation stacks
          "cloudformation:*",

          // Allow access to S3 for assets
          "s3:*",

          // Allow managing IAM roles and policies for resources
          "iam:*",

          // Allow managing EC2 resources including security groups
          "ec2:*",

          // Allow managing Auto Scaling Groups
          "autoscaling:*",

          // Allow managing CloudWatch resources
          "cloudwatch:*",
          "logs:*",

          // Allow managing Cloud Map resources
          "servicediscovery:*",

          // Allow managing Lambda functions
          "lambda:*",

          // Allow ECR access
          "ecr:*",

          // Allow managing custom resources and SSM parameters
          "ssm:*",
        ],
        resources: ["*"],
      })
    );

    // Create the pipeline
    const pipeline = new codepipeline.Pipeline(this, "LlmServicePipeline", {
      pipelineName: "LlmServicePipeline",
      restartExecutionOnUpdate: true,
    });

    // Add source stage - using GitHub as the source
    pipeline.addStage({
      stageName: "Source",
      actions: [
        new codepipeline_actions.GitHubSourceAction({
          actionName: "GitHub",
          owner: "jmau949", // GitHub username
          repo: "deepseek-llm-service", // GitHub repository name
          branch: "master", // Branch to monitor for changes
          output: sourceOutput,
          oauthToken: cdk.SecretValue.secretsManager(
            "deepseek-llm-service-pat",
            {
              jsonField: "github-token", // JSON field containing the token
            }
          ),
        }),
      ],
    });

    // Add build and push Docker image stage
    pipeline.addStage({
      stageName: "BuildDockerImage",
      actions: [
        new codepipeline_actions.CodeBuildAction({
          actionName: "BuildAndPushImage",
          project: buildProject,
          input: sourceOutput,
          outputs: [buildOutput],
        }),
      ],
    });

    // Add deploy infrastructure stage
    pipeline.addStage({
      stageName: "DeployInfrastructure",
      actions: [
        new codepipeline_actions.CodeBuildAction({
          actionName: "DeployStack",
          project: deployProject,
          input: sourceOutput,
          // No environmentVariables in the action, they're in the project definition
        }),
      ],
    });

    // Outputs
    new cdk.CfnOutput(this, "EcrRepositoryUri", {
      value: ecrRepository.repositoryUri,
      description: "The URI of the ECR repository",
    });

    new cdk.CfnOutput(this, "PipelineName", {
      value: pipeline.pipelineName,
      description: "The name of the CI/CD pipeline",
    });
  }
}
