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
                "COMMIT_HASH=$(echo $CODEBUILD_RESOLVED_SOURCE_VERSION | cut -c 1-7)",
                "IMAGE_TAG=${COMMIT_HASH:=latest}",
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
                "if [ -f ./service/Dockerfile ]; then echo 'Dockerfile found in service directory'; cd service; echo 'Changed to service directory: '$(pwd); ls -la; echo 'Building Docker image...'; docker build -t $ECR_REPOSITORY_URI:$IMAGE_TAG .; elif [ -f Dockerfile ]; then echo 'Dockerfile found in root directory'; echo 'Building Docker image...'; docker build -t $ECR_REPOSITORY_URI:$IMAGE_TAG .; else echo 'ERROR: Dockerfile not found in expected locations!'; find . -name 'Dockerfile' -type f; exit 1; fi",
                "echo 'Successfully built Docker image'",
                "docker tag $ECR_REPOSITORY_URI:$IMAGE_TAG $ECR_REPOSITORY_URI:latest",
              ],
            },
            post_build: {
              commands: [
                "echo Build completed on `date`",
                "if [ $CODEBUILD_BUILD_SUCCEEDING = 1 ]; then echo Pushing the Docker image...; echo Docker images available:; docker images; docker push $ECR_REPOSITORY_URI:$IMAGE_TAG; docker push $ECR_REPOSITORY_URI:latest; echo Successfully pushed Docker image; echo Writing image definition file...; cd $CODEBUILD_SRC_DIR; echo '{\"ImageURI\":\"'$ECR_REPOSITORY_URI:$IMAGE_TAG'\"}' > imageDefinition.json; echo Image definition file created:; cat imageDefinition.json; else echo Build failed, skipping Docker push; cd $CODEBUILD_SRC_DIR; echo '{\"ImageURI\":\"'$ECR_REPOSITORY_URI:latest'\"}' > imageDefinition.json; fi",
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
                "cd infrastructure",
                "npm install",
              ],
            },
            build: {
              commands: [
                "echo Deploying infrastructure...",
                "cd infrastructure && npx cdk deploy LlmServiceInfraStack --require-approval never",
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
