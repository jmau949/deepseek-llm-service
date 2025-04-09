import * as cdk from "aws-cdk-lib";
import * as codebuild from "aws-cdk-lib/aws-codebuild";
import * as codepipeline from "aws-cdk-lib/aws-codepipeline";
import * as codepipeline_actions from "aws-cdk-lib/aws-codepipeline-actions";
import * as ecr from "aws-cdk-lib/aws-ecr";
import * as iam from "aws-cdk-lib/aws-iam";
import { Construct } from "constructs";

export class CicdPipelineStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // Create an ECR repository for the Docker images
    const ecrRepository = new ecr.Repository(this, "LlmServiceEcrRepository", {
      repositoryName: "llm-service",
      removalPolicy: cdk.RemovalPolicy.RETAIN,
      lifecycleRules: [
        {
          maxImageCount: 10,
          description: "Only keep 10 latest images",
        },
      ],
    });

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
          buildImage: codebuild.LinuxBuildImage.STANDARD_5_0,
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
                "COMMIT_HASH=$(echo $CODEBUILD_RESOLVED_SOURCE_VERSION | cut -c 1-7)",
                "IMAGE_TAG=${COMMIT_HASH:=latest}",
              ],
            },
            build: {
              commands: [
                "echo Build started on `date`",
                "echo Building the Docker image...",
                "docker build -t $ECR_REPOSITORY_URI:$IMAGE_TAG .",
                "docker tag $ECR_REPOSITORY_URI:$IMAGE_TAG $ECR_REPOSITORY_URI:latest",
              ],
            },
            post_build: {
              commands: [
                "echo Build completed on `date`",
                "echo Pushing the Docker image...",
                "docker push $ECR_REPOSITORY_URI:$IMAGE_TAG",
                "docker push $ECR_REPOSITORY_URI:latest",
                "echo Writing image definition file...",
                'echo "{"ImageURI":"$ECR_REPOSITORY_URI:$IMAGE_TAG"}" > imageDefinition.json',
              ],
            },
          },
          artifacts: {
            files: ["imageDefinition.json"],
          },
        }),
      }
    );

    // Grant permissions to the CodeBuild project to push to ECR
    ecrRepository.grantPullPush(buildProject);

    // Create a CodeBuild project for deploying infrastructure
    const deployProject = new codebuild.PipelineProject(
      this,
      "LlmServiceDeploy",
      {
        environment: {
          buildImage: codebuild.LinuxBuildImage.STANDARD_5_0,
        },
        buildSpec: codebuild.BuildSpec.fromObject({
          version: "0.2",
          phases: {
            install: {
              commands: [
                "npm install -g aws-cdk",
                "cd infrastructure",
                "npm install",
              ],
            },
            build: {
              commands: [
                "echo Deploying infrastructure...",
                "cdk deploy LlmServiceInfraStack --require-approval never",
              ],
            },
          },
        }),
      }
    );

    // Grant permissions to the deploy project
    deployProject.role?.addManagedPolicy(
      iam.ManagedPolicy.fromAwsManagedPolicyName("AdministratorAccess")
    );

    // Create the pipeline
    const pipeline = new codepipeline.Pipeline(this, "LlmServicePipeline", {
      pipelineName: "LlmServicePipeline",
      restartExecutionOnUpdate: true,
    });

    // Add source stage - using GitHub as the source
    // You'll need to connect your GitHub repository to CodePipeline
    pipeline.addStage({
      stageName: "Source",
      actions: [
        new codepipeline_actions.GitHubSourceAction({
          actionName: "GitHub",
          owner: "jmau949", // Replace with your GitHub username
          repo: "deepseek-llm-service", // Replace with your repository name
          branch: "main",
          output: sourceOutput,
          oauthToken: cdk.SecretValue.secretsManager("github-token"), // Create this secret in AWS Secrets Manager
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
          environmentVariables: {
            IMAGE_URI: {
              value: buildOutput.getParam("imageDefinition.json", "ImageURI"),
            },
          },
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
