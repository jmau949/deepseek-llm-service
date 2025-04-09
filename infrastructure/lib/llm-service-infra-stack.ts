import * as cdk from "aws-cdk-lib";
import * as ec2 from "aws-cdk-lib/aws-ec2";
import * as autoscaling from "aws-cdk-lib/aws-autoscaling";
import * as iam from "aws-cdk-lib/aws-iam";
import * as servicediscovery from "aws-cdk-lib/aws-servicediscovery";
import * as lambda from "aws-cdk-lib/aws-lambda";
import * as logs from "aws-cdk-lib/aws-logs";
import { Construct } from "constructs";

export class LlmServiceInfraStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // Create a VPC
    const vpc = new ec2.Vpc(this, "LlmServiceVpc", {
      maxAzs: 2,
      natGateways: 1,
    });

    // Create Cloud Map namespace for service discovery
    const namespace = new servicediscovery.PrivateDnsNamespace(
      this,
      "LlmServiceNamespace",
      {
        name: "llm-service",
        vpc,
        description: "Namespace for LLM Service",
      }
    );

    // Create a service discovery service
    const service = namespace.createService("LlmService", {
      dnsRecordType: servicediscovery.DnsRecordType.A,
      dnsTtl: cdk.Duration.seconds(10),
      healthCheck: {
        type: servicediscovery.HealthCheckType.TCP,
        resourcePath: "/",
        failureThreshold: 2,
      },
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

    // Create IAM role for EC2 instances
    const instanceRole = new iam.Role(this, "LlmServiceInstanceRole", {
      assumedBy: new iam.ServicePrincipal("ec2.amazonaws.com"),
      managedPolicies: [
        iam.ManagedPolicy.fromAwsManagedPolicyName(
          "AmazonSSMManagedInstanceCore"
        ),
        iam.ManagedPolicy.fromAwsManagedPolicyName(
          "CloudWatchAgentServerPolicy"
        ),
      ],
    });

    // Add permissions to register with Cloud Map
    instanceRole.addToPrincipalPolicy(
      new iam.PolicyStatement({
        actions: [
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

      // Install AWS CloudWatch agent
      "yum install -y amazon-cloudwatch-agent",
      "systemctl start amazon-cloudwatch-agent",

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
        instanceType: ec2.InstanceType.of(
          ec2.InstanceClass.T3,
          ec2.InstanceSize.MICRO
        ),
        userData,
        securityGroup: llmServiceSg,
        role: instanceRole,
      }
    );

    // Create Auto Scaling Group with spot instances
    const asg = new autoscaling.AutoScalingGroup(this, "LlmServiceAsg", {
      vpc,
      launchTemplate,
      minCapacity: 2,
      maxCapacity: 10,
      desiredCapacity: 2,
      spotPrice: "0.50", // Set a maximum spot price (adjust based on market prices)
      instanceMonitoring: autoscaling.Monitoring.DETAILED, // Enable detailed CloudWatch monitoring
      healthCheck: autoscaling.HealthCheck.ec2({
        grace: cdk.Duration.minutes(5),
      }),
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
  }
}
