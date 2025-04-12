import * as cdk from "aws-cdk-lib";
import * as ec2 from "aws-cdk-lib/aws-ec2";
import * as autoscaling from "aws-cdk-lib/aws-autoscaling";
import * as iam from "aws-cdk-lib/aws-iam";
import * as servicediscovery from "aws-cdk-lib/aws-servicediscovery";
import * as lambda from "aws-cdk-lib/aws-lambda";
import * as logs from "aws-cdk-lib/aws-logs";
import * as ecr from "aws-cdk-lib/aws-ecr";
import * as ssm from "aws-cdk-lib/aws-ssm";
import { Construct } from "constructs";

export class LlmServiceInfraStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // Retrieve shared infrastructure values from SSM Parameter Store
    const vpcId = ssm.StringParameter.valueForStringParameter(
      this,
      "/deepseek-llm-service/SharedAiServicesVpcId"
    );

    const subnet1Id = ssm.StringParameter.valueForStringParameter(
      this,
      "/deepseek-llm-service/SharedAiServicesPrivateSubnet1Id"
    );

    const llmServiceSgId = ssm.StringParameter.valueForStringParameter(
      this,
      "/deepseek-llm-service/SharedAiServicesLlmServiceSgId"
    );

    const lambdaClientSgId = ssm.StringParameter.valueForStringParameter(
      this,
      "/deepseek-llm-service/SharedAiServicesLambdaClientSgId"
    );

    const namespaceId = ssm.StringParameter.valueForStringParameter(
      this,
      "/deepseek-llm-service/SharedAiServicesNamespaceId"
    );

    const namespaceName = ssm.StringParameter.valueForStringParameter(
      this,
      "/deepseek-llm-service/SharedAiServicesNamespaceName"
    );

    // Import the VPC from the shared infrastructure stack using VpcAttributes
    // This is more compatible with tokens from SSM than Vpc.fromLookup()
    const vpc = ec2.Vpc.fromVpcAttributes(this, "SharedVpc", {
      vpcId: vpcId,
      availabilityZones: [cdk.Stack.of(this).availabilityZones[0]],
      privateSubnetIds: [subnet1Id],
    });

    // Import security groups from the shared infrastructure
    const llmServiceSg = ec2.SecurityGroup.fromSecurityGroupId(
      this,
      "LlmServiceSg",
      llmServiceSgId
    );

    const lambdaClientSg = ec2.SecurityGroup.fromSecurityGroupId(
      this,
      "LambdaClientSg",
      lambdaClientSgId
    );

    // Import the existing service created by the VPC stack
    const serviceId = ssm.StringParameter.valueForStringParameter(
      this,
      "/deepseek-llm-service/SharedAiServicesLlmServiceId"
    );

    const serviceName = ssm.StringParameter.valueForStringParameter(
      this,
      "/deepseek-llm-service/SharedAiServicesLlmServiceName"
    );

    const service = servicediscovery.Service.fromServiceAttributes(
      this,
      "DeepseekLlmService",
      {
        serviceName,
        serviceId,
        serviceArn: `arn:aws:servicediscovery:${this.region}:${this.account}:service/${serviceId}`,
        dnsRecordType: servicediscovery.DnsRecordType.A,
        routingPolicy: servicediscovery.RoutingPolicy.WEIGHTED,
        namespace:
          servicediscovery.PrivateDnsNamespace.fromPrivateDnsNamespaceAttributes(
            this,
            "AiServicesNamespace",
            {
              namespaceName,
              namespaceId,
              namespaceArn: `arn:aws:servicediscovery:${this.region}:${this.account}:namespace/${namespaceId}`,
            }
          ),
      }
    );

    // Create IAM role for EC2 instances
    const instanceRole = new iam.Role(this, "LlmServiceInstanceRole", {
      assumedBy: new iam.ServicePrincipal("ec2.amazonaws.com"),
      managedPolicies: [],
    });

    // Add permissions to use ECR and register with Cloud Map
    instanceRole.addToPrincipalPolicy(
      new iam.PolicyStatement({
        actions: [
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage",
          "ecr:BatchCheckLayerAvailability",
          "ecr:GetAuthorizationToken",
          "servicediscovery:RegisterInstance",
          "servicediscovery:DeregisterInstance",
          "servicediscovery:DiscoverInstances",
        ],
        resources: ["*"],
      })
    );

    // Create launch template for ASG
    const userData = ec2.UserData.forLinux();
    userData.addCommands(
      "yum update -y",
      "yum install -y docker",
      "systemctl start docker",
      "systemctl enable docker",

      // Pull and run the LLM service container
      "aws ecr get-login-password --region " +
        this.region +
        " | docker login --username AWS --password-stdin " +
        this.account +
        ".dkr.ecr." +
        this.region +
        ".amazonaws.com",
      // Replace with your actual ECR repository and image tag
      "docker pull ${this.account}.dkr.ecr.${this.region}.amazonaws.com/llm-service:latest",

      // Run the container with environment variables
      'docker run -d --restart always -p 50051:50051 -e MODEL_NAME="deepseek-r1:1.5b" ${this.account}.dkr.ecr.${this.region}.amazonaws.com/llm-service:latest',

      // Register with Cloud Map
      // We'll use the EC2 instance's IP address for registration
      "INSTANCE_ID=$(curl -s http://169.254.169.254/latest/meta-data/instance-id)",
      "PRIVATE_IP=$(curl -s http://169.254.169.254/latest/meta-data/local-ipv4)",

      // Register the instance with AWS Cloud Map
      "aws servicediscovery register-instance --service-id ${service.serviceId} --instance-id $INSTANCE_ID --attributes AWS_INSTANCE_IPV4=$PRIVATE_IP,AWS_INSTANCE_PORT=50051 --region " +
        this.region
    );

    const launchTemplate = new ec2.LaunchTemplate(
      this,
      "LlmServiceLaunchTemplate",
      {
        machineImage: ec2.MachineImage.latestAmazonLinux2(),
        instanceType: new ec2.InstanceType("c5.2xlarge"),
        userData,
        securityGroup: llmServiceSg,
        role: instanceRole,
        spotOptions: {
          requestType: ec2.SpotRequestType.ONE_TIME,
          maxPrice: 0.25,
        },
      }
    );

    // Create Auto Scaling Group with spot instances
    const asg = new autoscaling.AutoScalingGroup(this, "LlmServiceAsg", {
      vpc,
      vpcSubnets: {
        subnets: vpc.privateSubnets,
      },
      launchTemplate,
      minCapacity: 0,
      maxCapacity: 0,
      instanceMonitoring: autoscaling.Monitoring.BASIC, // Use basic monitoring to save costs
      updatePolicy: autoscaling.UpdatePolicy.rollingUpdate(),
    });

    // Add scaling policies based on CPU usage
    asg.scaleOnCpuUtilization("CpuScaling", {
      targetUtilizationPercent: 70,
      cooldown: cdk.Duration.seconds(300),
    });

    // Add scheduled action to stop instances at 12am Central Time (6am UTC)
    asg.scaleOnSchedule("StopAtMidnight", {
      schedule: autoscaling.Schedule.cron({ hour: "6", minute: "0" }),
      minCapacity: 0,
      maxCapacity: 0,
      desiredCapacity: 0,
    });

    // Add scheduled action to start instances at 9am Central Time (3pm UTC)
    asg.scaleOnSchedule("StartAtNineAM", {
      schedule: autoscaling.Schedule.cron({ hour: "15", minute: "0" }),
      minCapacity: 0,
      maxCapacity: 0,
      desiredCapacity: 0,
    });

    // Outputs
    new cdk.CfnOutput(this, "NamespaceId", {
      value: namespaceId,
      description: "The ID of the Cloud Map namespace",
    });

    new cdk.CfnOutput(this, "ServiceId", {
      value: service.serviceId,
      description: "The ID of the Cloud Map service",
    });

    // Output service discovery service name for WebSocket Lambda
    new cdk.CfnOutput(this, "ServiceDiscoveryServiceName", {
      value: service.serviceName,
      description: "The name of the Cloud Map service",
      exportName: "DeepseekLlmServiceName",
    });

    // Output Lambda security group ID for WebSocket Lambda
    new cdk.CfnOutput(this, "LambdaClientSecurityGroupId", {
      value: lambdaClientSg.securityGroupId,
      description:
        "Security Group ID for Lambda functions to connect to LLM service",
      exportName: "LlmServiceLambdaClientSgId",
    });
  }
}