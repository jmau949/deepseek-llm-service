import * as cdk from "aws-cdk-lib";
import * as ec2 from "aws-cdk-lib/aws-ec2";
import * as autoscaling from "aws-cdk-lib/aws-autoscaling";
import * as iam from "aws-cdk-lib/aws-iam";
import * as servicediscovery from "aws-cdk-lib/aws-servicediscovery";
import * as lambda from "aws-cdk-lib/aws-lambda";
import * as logs from "aws-cdk-lib/aws-logs";
import * as ecr from "aws-cdk-lib/aws-ecr";
import { Construct } from "constructs";

export class LlmServiceInfraStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // Create a VPC
    const vpc = new ec2.Vpc(this, "LlmServiceVpc", {
      maxAzs: 1,
      natGateways: 0,
      ipAddresses: ec2.IpAddresses.cidr("172.16.0.0/16"), // Updated from deprecated 'cidr'
      subnetConfiguration: [
        {
          name: "private",
          subnetType: ec2.SubnetType.PRIVATE_ISOLATED,
          cidrMask: 24,
        },
      ],
      // Default security group will be restricted as a security best practice
    });

    // Only keep essential VPC endpoints
    vpc.addInterfaceEndpoint("EcrDockerEndpoint", {
      service: ec2.InterfaceVpcEndpointAwsService.ECR_DOCKER,
    });

    vpc.addInterfaceEndpoint("EcrEndpoint", {
      service: ec2.InterfaceVpcEndpointAwsService.ECR,
    });

    vpc.addGatewayEndpoint("S3Endpoint", {
      service: ec2.GatewayVpcEndpointAwsService.S3,
    });

    // Add interface endpoint for AWS API calls (for servicediscovery)
    new ec2.InterfaceVpcEndpoint(this, "ServiceDiscoveryEndpoint", {
      vpc,
      service: new ec2.InterfaceVpcEndpointService(
        "com.amazonaws." + this.region + ".servicediscovery"
      ),
      privateDnsEnabled: true,
    });

    // Add endpoint for DynamoDB
    vpc.addGatewayEndpoint("DynamoDBEndpoint", {
      service: ec2.GatewayVpcEndpointAwsService.DYNAMODB,
    });

    // Add endpoint for CloudWatch Logs
    new ec2.InterfaceVpcEndpoint(this, "CloudWatchLogsEndpoint", {
      vpc,
      service: new ec2.InterfaceVpcEndpointService(
        "com.amazonaws." + this.region + ".logs"
      ),
      privateDnsEnabled: true,
    });

    // Create Cloud Map namespace for service discovery
    const namespace = new servicediscovery.PrivateDnsNamespace(
      this,
      "AiServicesNamespace",
      {
        name: "ai-services.local",
        vpc,
        description: "Namespace for AI Language Model Services",
      }
    );

    // Create a service discovery service
    const service = namespace.createService("DeepseekLlmService", {
      name: "deepseek-llm",
      dnsRecordType: servicediscovery.DnsRecordType.A,
      dnsTtl: cdk.Duration.seconds(10),
      description: "DeepSeek LLM service for inference",
    });

    // Security group for LLM service instances
    const llmServiceSg = new ec2.SecurityGroup(this, "LlmServiceSg", {
      vpc,
      description: "Security group for LLM Service instances",
      allowAllOutbound: true,
    });

    // Allow incoming gRPC traffic (port 50051)
    llmServiceSg.addIngressRule(
      ec2.Peer.anyIpv4(),
      ec2.Port.tcp(50051),
      "Allow gRPC traffic"
    );

    // Security group for Lambda functions to connect to LLM service
    const lambdaClientSg = new ec2.SecurityGroup(this, "LambdaClientSg", {
      vpc,
      description:
        "Security group for Lambda functions connecting to LLM Service",
      allowAllOutbound: false,
    });

    // Allow Lambda to connect to LLM service
    lambdaClientSg.addEgressRule(
      llmServiceSg,
      ec2.Port.tcp(50051),
      "Allow Lambda to connect to LLM service"
    );

    // Allow Lambda outbound HTTPS access for AWS services via VPC endpoints
    lambdaClientSg.addEgressRule(
      ec2.Peer.anyIpv4(),
      ec2.Port.tcp(443),
      "Allow HTTPS outbound traffic for AWS services"
    );

    // LLM service should accept connections from Lambda
    llmServiceSg.addIngressRule(
      lambdaClientSg,
      ec2.Port.tcp(50051),
      "Allow Lambda clients to connect"
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
        instanceType: new ec2.InstanceType("g4dn.large"),
        //   ec2.InstanceClass.G4DN,
        //   ec2.InstanceSize.LARGE
        // ),
        userData,
        securityGroup: llmServiceSg,
        role: instanceRole,
        spotOptions: {
          requestType: ec2.SpotRequestType.ONE_TIME,
          maxPrice: 0.3, // Very low spot price for t3.micro instances
        },
      }
    );

    // Create Auto Scaling Group with spot instances
    const asg = new autoscaling.AutoScalingGroup(this, "LlmServiceAsg", {
      vpc,
      launchTemplate,
      minCapacity: 1,
      maxCapacity: 2,
      // Remove desiredCapacity to avoid the warning and constant resetting
      // desiredCapacity: 1,
      instanceMonitoring: autoscaling.Monitoring.BASIC, // Use basic monitoring to save costs

      // Simpler approach - don't specify any custom health check
      // to avoid the deprecated APIs and the linter errors
      updatePolicy: autoscaling.UpdatePolicy.rollingUpdate(),
    });

    // Add scaling policies based on CPU usage
    asg.scaleOnCpuUtilization("CpuScaling", {
      targetUtilizationPercent: 70,
      cooldown: cdk.Duration.seconds(300),
    });

    // Outputs
    new cdk.CfnOutput(this, "NamespaceId", {
      value: namespace.namespaceId,
      description: "The ID of the Cloud Map namespace",
    });

    new cdk.CfnOutput(this, "ServiceId", {
      value: service.serviceId,
      description: "The ID of the Cloud Map service",
    });

    new cdk.CfnOutput(this, "VpcId", {
      value: vpc.vpcId,
      description: "The ID of the VPC",
      exportName: "LlmServiceVpcId",
    });

    // Output the private subnet IDs for use by Lambda function in websocket repo
    for (let i = 0; i < vpc.privateSubnets.length; i++) {
      new cdk.CfnOutput(this, `PrivateSubnet${i + 1}Id`, {
        value: vpc.privateSubnets[i].subnetId,
        description: `The ID of private subnet ${i + 1}`,
        exportName: `LlmServicePrivateSubnet${i + 1}Id`,
      });
    }

    // Output the security group ID for Lambda to use
    new cdk.CfnOutput(this, "LambdaClientSecurityGroupId", {
      value: lambdaClientSg.securityGroupId,
      description:
        "Security Group ID for Lambda functions to connect to LLM service",
      exportName: "LlmServiceLambdaClientSgId",
    });

    // Output service discovery namespace name
    new cdk.CfnOutput(this, "ServiceDiscoveryNamespaceName", {
      value: namespace.namespaceName,
      description: "The name of the Cloud Map namespace",
      exportName: "AiServicesNamespaceName",
    });

    // Output service discovery service name
    new cdk.CfnOutput(this, "ServiceDiscoveryServiceName", {
      value: service.serviceName,
      description: "The name of the Cloud Map service",
      exportName: "DeepseekLlmServiceName",
    });
  }
}
