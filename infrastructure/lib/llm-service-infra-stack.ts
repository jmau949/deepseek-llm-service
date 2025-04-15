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

export interface LlmServiceInfraStackProps extends cdk.StackProps {
  environmentName?: string;
  serviceDiscoveryPrefix?: string;
  llmServicePort?: number;
  modelName?: string;
}

export class LlmServiceInfraStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: LlmServiceInfraStackProps) {
    super(scope, id, props);

    // Use provided values or defaults - defaulting to the paths used in VpcInfrastructureStack
    const serviceDiscoveryPrefix =
      props?.serviceDiscoveryPrefix || "/deepseek-llm-service";
    const llmServicePort = props?.llmServicePort || 50051;
    const modelName = props?.modelName || "deepseek-r1:1.5b";

    try {
      // Retrieve shared infrastructure values from SSM Parameter Store
      const vpcId = ssm.StringParameter.valueForStringParameter(
        this,
        `${serviceDiscoveryPrefix}/SharedAiServicesVpcId`
      );

      const subnet1Id = ssm.StringParameter.valueForStringParameter(
        this,
        `${serviceDiscoveryPrefix}/SharedAiServicesPrivateSubnet1Id`
      );

      const llmServiceSgId = ssm.StringParameter.valueForStringParameter(
        this,
        `${serviceDiscoveryPrefix}/SharedAiServicesLlmServiceSgId`
      );

      const lambdaClientSgId = ssm.StringParameter.valueForStringParameter(
        this,
        `${serviceDiscoveryPrefix}/SharedAiServicesLambdaClientSgId`
      );

      const namespaceId = ssm.StringParameter.valueForStringParameter(
        this,
        `${serviceDiscoveryPrefix}/SharedAiServicesNamespaceId`
      );

      const namespaceName = ssm.StringParameter.valueForStringParameter(
        this,
        `${serviceDiscoveryPrefix}/SharedAiServicesNamespaceName`
      );

      const vpcCidrBlock = ssm.StringParameter.valueForStringParameter(
        this,
        `${serviceDiscoveryPrefix}/SharedAiServicesVpcCidrBlock`
      );

      // Import the VPC from the shared infrastructure stack using VpcAttributes
      // This is more compatible with tokens from SSM than Vpc.fromLookup()
      // Note: The updated VPC infrastructure uses isolated subnets, but the property name is still privateSubnetIds
      const vpc = ec2.Vpc.fromVpcAttributes(this, "SharedVpc", {
        vpcId: vpcId,
        availabilityZones: [cdk.Stack.of(this).availabilityZones[0]],
        isolatedSubnetIds: [subnet1Id], // Updated to use isolatedSubnetIds
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
        `${serviceDiscoveryPrefix}/SharedAiServicesLlmServiceId`
      );

      const serviceName = ssm.StringParameter.valueForStringParameter(
        this,
        `${serviceDiscoveryPrefix}/SharedAiServicesLlmServiceName`
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
        `aws ecr get-login-password --region ${this.region} | docker login --username AWS --password-stdin ${this.account}.dkr.ecr.${this.region}.amazonaws.com`,
        // Pull the container image
        `docker pull ${this.account}.dkr.ecr.${this.region}.amazonaws.com/llm-service:latest`,

        // Run the container with environment variables
        `docker run -d --restart always -p ${llmServicePort}:${llmServicePort} -e MODEL_NAME="${modelName}" ${this.account}.dkr.ecr.${this.region}.amazonaws.com/llm-service:latest`,

        // Register with Cloud Map
        // We'll use the EC2 instance's IP address for registration
        "INSTANCE_ID=$(curl -s http://169.254.169.254/latest/meta-data/instance-id)",
        "PRIVATE_IP=$(curl -s http://169.254.169.254/latest/meta-data/local-ipv4)",

        // Register the instance with AWS Cloud Map
        `aws servicediscovery register-instance --service-id ${serviceId} --instance-id $INSTANCE_ID --attributes AWS_INSTANCE_IPV4=$PRIVATE_IP,AWS_INSTANCE_PORT=${llmServicePort} --region ${this.region}`
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
      // We need to directly reference the subnet by ID since we're using a hard-coded value
      const subnetId = subnet1Id; // This is the value from SSM Parameter Store
      const subnet = ec2.Subnet.fromSubnetId(this, "IsolatedSubnet1", subnetId);

      const asg = new autoscaling.AutoScalingGroup(this, "LlmServiceAsg", {
        vpc,
        vpcSubnets: {
          subnets: [subnet], // Use explicit subnet reference
        },
        launchTemplate,
        minCapacity: 0,
        maxCapacity: 0, // Updated to allow scaling to 1 instance
        desiredCapacity: 0,
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
      new cdk.CfnOutput(this, "VpcId", {
        value: vpcId,
        description: "The ID of the VPC",
      });

      new cdk.CfnOutput(this, "NamespaceId", {
        value: namespaceId,
        description: "The ID of the Cloud Map namespace",
      });

      new cdk.CfnOutput(this, "ServiceId", {
        value: service.serviceId,
        description: "The ID of the Cloud Map service",
      });

      new cdk.CfnOutput(this, "ServiceDiscoveryServiceName", {
        value: service.serviceName,
        description: "The name of the Cloud Map service",
        exportName: "DeepseekLlmServiceName",
      });

      new cdk.CfnOutput(this, "LambdaClientSecurityGroupId", {
        value: lambdaClientSg.securityGroupId,
        description:
          "Security Group ID for Lambda functions to connect to LLM service",
        exportName: "LlmServiceLambdaClientSgId",
      });
    } catch (error) {
      console.error("Error retrieving SSM parameters:", error);
      throw new Error(`Failed to initialize LlmServiceInfraStack: ${error}`);
    }
  }
}