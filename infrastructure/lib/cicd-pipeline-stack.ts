/**
 * This file defines a CI/CD pipeline for the DeepSeek LLM Service using AWS CDK.
 * The pipeline automates building a Docker image and deploying infrastructure.
 */

// Import necessary AWS CDK libraries
import * as cdk from "aws-cdk-lib"; // Core CDK library
import * as codebuild from "aws-cdk-lib/aws-codebuild"; // For AWS CodeBuild resources
import * as codepipeline from "aws-cdk-lib/aws-codepipeline"; // For AWS CodePipeline resources
import * as codepipeline_actions from "aws-cdk-lib/aws-codepipeline-actions"; // For CodePipeline actions
import * as ecr from "aws-cdk-lib/aws-ecr"; // For Amazon ECR (Elastic Container Registry)
import * as iam from "aws-cdk-lib/aws-iam"; // For AWS IAM roles and policies
import { Construct } from "constructs"; // For CDK construct pattern

/**
 * Stack that defines the complete CI/CD pipeline for the LLM service
 */
export class CicdPipelineStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // Import the existing ECR repository instead of creating a new one
    // This is where our Docker images will be stored
    const ecrRepository = ecr.Repository.fromRepositoryName(
      this,
      "LlmServiceEcrRepository",
      "llm-service"
    );

    // Define the artifact for source code
    // This will store the code pulled from the GitHub repository
    const sourceOutput = new codepipeline.Artifact("SourceCode");

    // Define the artifact for built container image
    // This will store information about the built Docker image
    const buildOutput = new codepipeline.Artifact("BuildOutput");

    /**
     * Create a CodeBuild project for building Docker images
     * This project will:
     * 1. Authenticate with ECR
     * 2. Build a Docker image from the source code
     * 3. Tag the image with both the commit hash and 'latest'
     * 4. Push the images to ECR
     */
    const buildProject = new codebuild.PipelineProject(
      this,
      "LlmServiceBuild",
      {
        environment: {
          buildImage: codebuild.LinuxBuildImage.STANDARD_5_0, // Use AWS Linux image with build tools
          privileged: true, // Required for Docker builds (to use Docker daemon)
        },
        // Environment variables available during the build
        environmentVariables: {
          ECR_REPOSITORY_URI: {
            value: ecrRepository.repositoryUri, // URI of our ECR repository
          },
          AWS_ACCOUNT_ID: {
            value: this.account, // Current AWS account ID from context
          },
          AWS_REGION: {
            value: this.region, // Current AWS region from context
          },
        },
        // Define the commands to execute during build phases
        buildSpec: codebuild.BuildSpec.fromObject({
          version: "0.2",
          phases: {
            // Pre-build phase: setup authentication and prepare image tagging
            pre_build: {
              commands: [
                "echo Logging in to Amazon ECR...",
                // Authenticate with ECR using AWS CLI
                "aws ecr get-login-password --region $AWS_REGION | docker login --username AWS --password-stdin $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com",
                // Create a short commit hash to use as image tag
                "COMMIT_HASH=$(echo $CODEBUILD_RESOLVED_SOURCE_VERSION | cut -c 1-7)",
                // Use the commit hash as tag, defaulting to 'latest' if not available
                "IMAGE_TAG=${COMMIT_HASH:=latest}",
              ],
            },
            // Build phase: build and tag the Docker image
            build: {
              commands: [
                "echo Build started on `date`",
                "echo Building the Docker image...",
                // Build the Docker image with the commit hash tag
                "docker build -t $ECR_REPOSITORY_URI:$IMAGE_TAG .",
                // Also tag the image as 'latest'
                "docker tag $ECR_REPOSITORY_URI:$IMAGE_TAG $ECR_REPOSITORY_URI:latest",
              ],
            },
            // Post-build phase: push the image to ECR and create image definition file
            post_build: {
              commands: [
                "echo Build completed on `date`",
                "echo Pushing the Docker image...",
                // Push the image with commit hash tag
                "docker push $ECR_REPOSITORY_URI:$IMAGE_TAG",
                // Push the image with 'latest' tag
                "docker push $ECR_REPOSITORY_URI:latest",
                "echo Writing image definition file...",
                // Create a JSON file with image URI for later use by deployment
                'echo "{"ImageURI":"$ECR_REPOSITORY_URI:$IMAGE_TAG"}" > imageDefinition.json',
              ],
            },
          },
          // Define artifacts to store from the build
          artifacts: {
            files: ["imageDefinition.json"], // Save the image definition for later stages
          },
        }),
      }
    );

    // Grant permissions to the CodeBuild project to push to ECR
    // This allows the build project to pull and push Docker images
    ecrRepository.grantPullPush(buildProject);

    /**
     * Create a CodeBuild project for deploying infrastructure
     * This project will:
     * 1. Install necessary tools (AWS CDK)
     * 2. Deploy the infrastructure stack using CDK
     */
    const deployProject = new codebuild.PipelineProject(
      this,
      "LlmServiceDeploy",
      {
        environment: {
          buildImage: codebuild.LinuxBuildImage.STANDARD_5_0, // Use AWS Linux image with build tools
        },
        // Environment variables available during deployment
        environmentVariables: {
          IMAGE_URI: {
            value: buildOutput.artifactName, // Reference to the build output artifact
            type: codebuild.BuildEnvironmentVariableType.PLAINTEXT,
          },
          ECR_REPOSITORY_URI: {
            value: ecrRepository.repositoryUri, // URI of our ECR repository
            type: codebuild.BuildEnvironmentVariableType.PLAINTEXT,
          },
        },
        // Define the commands to execute during deployment phases
        buildSpec: codebuild.BuildSpec.fromObject({
          version: "0.2",
          phases: {
            // Install phase: install AWS CDK and project dependencies
            install: {
              commands: [
                "npm install -g aws-cdk", // Install AWS CDK globally
                "cd infrastructure", // Navigate to infrastructure directory
                "npm install", // Install dependencies for CDK project
              ],
            },
            // Build phase: deploy the infrastructure stack
            build: {
              commands: [
                "echo Deploying infrastructure...",
                // Deploy the infrastructure stack without requiring manual approval
                "npx cdk deploy LlmServiceInfraStack --require-approval never",
              ],
            },
          },
        }),
      }
    );

    // Grant administrative permissions to the deploy project
    // This is needed for the deployment to create/update all necessary AWS resources
    // NOTE: In production, it's better to use more restrictive permissions
    deployProject.role?.addManagedPolicy(
      iam.ManagedPolicy.fromAwsManagedPolicyName("AdministratorAccess")
    );

    /**
     * Create the main CodePipeline with a unique name
     * This pipeline will orchestrate the entire CI/CD process
     */
    const pipeline = new codepipeline.Pipeline(this, "LlmServicePipeline", {
      pipelineName: "LlmServicePipeline-v1", // Unique pipeline name with version
      restartExecutionOnUpdate: true, // Auto-restart pipeline when it's updated
    });

    /**
     * Add Source Stage to the pipeline
     * This stage pulls code from GitHub when changes are detected
     */
    pipeline.addStage({
      stageName: "Source",
      actions: [
        new codepipeline_actions.GitHubSourceAction({
          actionName: "GitHub",
          owner: "jmau949", // GitHub username
          repo: "deepseek-llm-service", // GitHub repository name
          branch: "master", // Branch to monitor for changes
          output: sourceOutput, // Where to store the source code
          // Get GitHub authentication token from AWS Secrets Manager
          oauthToken: cdk.SecretValue.secretsManager(
            "deepseek-llm-service-pat", // Name of the secret in Secrets Manager
            {
              jsonField: "github-token", // JSON field containing the token
            }
          ),
        }),
      ],
    });

    /**
     * Add Build Stage to the pipeline
     * This stage builds the Docker image and pushes it to ECR
     */
    pipeline.addStage({
      stageName: "BuildDockerImage",
      actions: [
        new codepipeline_actions.CodeBuildAction({
          actionName: "BuildAndPushImage",
          project: buildProject, // Reference to the build project defined earlier
          input: sourceOutput, // Use source code as input
          outputs: [buildOutput], // Store build results in buildOutput artifact
        }),
      ],
    });

    /**
     * Add Deploy Stage to the pipeline
     * This stage deploys the infrastructure using CDK
     */
    pipeline.addStage({
      stageName: "DeployInfrastructure",
      actions: [
        new codepipeline_actions.CodeBuildAction({
          actionName: "DeployStack",
          project: deployProject, // Reference to the deploy project defined earlier
          input: sourceOutput, // Use source code as input
          // Environment variables are defined in the project, not here
        }),
      ],
    });

    /**
     * Create CloudFormation outputs to provide important information
     * These will be visible in the AWS CloudFormation console
     */
    // Output the ECR repository URI
    new cdk.CfnOutput(this, "EcrRepositoryUri", {
      value: ecrRepository.repositoryUri,
      description: "The URI of the ECR repository",
    });

    // Output the pipeline name
    new cdk.CfnOutput(this, "PipelineName", {
      value: pipeline.pipelineName,
      description: "The name of the CI/CD pipeline",
    });
  }
}
